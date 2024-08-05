/*++

Licensed under the Apache-2.0 license.

File Name:

    fake.rs

Abstract:

    File contains the implementation of the fake ROM reset flows

--*/

#[cfg(not(feature = "fake-rom"))]
compile_error!("This file should NEVER be included except for the fake-rom feature");

#[allow(dead_code)]
#[path = "cold_reset/fw_processor.rs"]
mod fw_processor;

use crate::fht;
use crate::flow::update_reset;
use crate::flow::warm_reset;
use crate::print::HexBytes;
use crate::rom_env::RomEnv;
use caliptra_common::RomBootStatus::*;
use caliptra_common::{
    memory_layout::{FMCALIAS_TBS_ORG, FMCALIAS_TBS_SIZE, LDEVID_TBS_ORG, LDEVID_TBS_SIZE},
    FirmwareHandoffTable,
};
use caliptra_drivers::cprintln;
use caliptra_drivers::Lifecycle;
use caliptra_drivers::LmsResult;
use caliptra_drivers::VendorPubKeyRevocation;
use caliptra_drivers::*;
use caliptra_error::CaliptraError;
use caliptra_image_types::*;
use caliptra_image_verify::ImageVerificationEnv;
use core::ops::Range;
use fw_processor::FirmwareProcessor;

const FAKE_LDEV_TBS: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/ldev_tbs.der"));
const FAKE_LDEV_PUB_KEY: Ecc384PubKey = Ecc384PubKey {
    x: Array4xN([
        0x842C00AF, 0x05ACCCEB, 0x14514E2D, 0x37B0C3AA, 0xA218F150, 0x57F1DCB8, 0x24A21498,
        0x0B744688, 0xA0888A02, 0x97FA7DC5, 0xE1EAD8CA, 0x1291DB22,
    ]),
    y: Array4xN([
        0x9C28EB86, 0x78BCE800, 0x822C0722, 0x8F416AE4, 0x9D218E5D, 0xA2F2D1A8, 0xA27DC19A,
        0xDF668A74, 0x628999D2, 0x22B40159, 0xD8076FAF, 0xBB8C5EDB,
    ]),
};
const FAKE_LDEV_SIG: Ecc384Signature = Ecc384Signature {
    r: Array4xN(include!(concat!(env!("OUT_DIR"), "/ldev_sig_r_words.txt"))),
    s: Array4xN(include!(concat!(env!("OUT_DIR"), "/ldev_sig_s_words.txt"))),
};

const FAKE_FMC_ALIAS_TBS: [u8; 745] = [
    0x30, 0x82, 0x02, 0xe5, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x14, 0x06, 0xb0, 0xfb, 0xb6, 0x60,
    0x59, 0xb8, 0x54, 0x55, 0xea, 0xc8, 0x95, 0x65, 0xc0, 0xc3, 0x7b, 0x67, 0x0f, 0xb1, 0x87, 0x30,
    0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03, 0x30, 0x65, 0x31, 0x18, 0x30,
    0x16, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x0f, 0x43, 0x61, 0x6c, 0x69, 0x70, 0x74, 0x72, 0x61,
    0x20, 0x4c, 0x44, 0x65, 0x76, 0x49, 0x44, 0x31, 0x49, 0x30, 0x47, 0x06, 0x03, 0x55, 0x04, 0x05,
    0x13, 0x40, 0x32, 0x31, 0x45, 0x45, 0x45, 0x46, 0x39, 0x41, 0x34, 0x43, 0x36, 0x31, 0x44, 0x34,
    0x42, 0x39, 0x45, 0x33, 0x44, 0x39, 0x34, 0x42, 0x45, 0x41, 0x34, 0x36, 0x46, 0x39, 0x41, 0x31,
    0x32, 0x41, 0x43, 0x36, 0x38, 0x38, 0x37, 0x43, 0x45, 0x32, 0x31, 0x38, 0x38, 0x35, 0x35, 0x39,
    0x46, 0x34, 0x30, 0x46, 0x46, 0x39, 0x35, 0x37, 0x37, 0x37, 0x45, 0x38, 0x30, 0x31, 0x34, 0x38,
    0x38, 0x39, 0x30, 0x22, 0x18, 0x0f, 0x32, 0x30, 0x32, 0x33, 0x30, 0x31, 0x30, 0x31, 0x30, 0x30,
    0x30, 0x30, 0x30, 0x30, 0x5a, 0x18, 0x0f, 0x39, 0x39, 0x39, 0x39, 0x31, 0x32, 0x33, 0x31, 0x32,
    0x33, 0x35, 0x39, 0x35, 0x39, 0x5a, 0x30, 0x68, 0x31, 0x1b, 0x30, 0x19, 0x06, 0x03, 0x55, 0x04,
    0x03, 0x0c, 0x12, 0x43, 0x61, 0x6c, 0x69, 0x70, 0x74, 0x72, 0x61, 0x20, 0x46, 0x4d, 0x43, 0x20,
    0x41, 0x6c, 0x69, 0x61, 0x73, 0x31, 0x49, 0x30, 0x47, 0x06, 0x03, 0x55, 0x04, 0x05, 0x13, 0x40,
    0x38, 0x32, 0x42, 0x30, 0x46, 0x42, 0x42, 0x36, 0x36, 0x30, 0x35, 0x39, 0x42, 0x38, 0x35, 0x34,
    0x35, 0x35, 0x45, 0x41, 0x43, 0x38, 0x39, 0x35, 0x36, 0x35, 0x43, 0x30, 0x43, 0x33, 0x37, 0x42,
    0x36, 0x37, 0x30, 0x46, 0x42, 0x31, 0x38, 0x37, 0x45, 0x30, 0x33, 0x31, 0x46, 0x38, 0x36, 0x31,
    0x37, 0x37, 0x46, 0x32, 0x46, 0x43, 0x34, 0x42, 0x31, 0x35, 0x32, 0x44, 0x43, 0x43, 0x43, 0x41,
    0x30, 0x76, 0x30, 0x10, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x05, 0x2b,
    0x81, 0x04, 0x00, 0x22, 0x03, 0x62, 0x00, 0x04, 0xd7, 0x4c, 0x25, 0xc3, 0x71, 0xbb, 0x0f, 0x48,
    0x9b, 0x1e, 0x20, 0x2c, 0x67, 0x57, 0xcf, 0x47, 0xd2, 0x82, 0xc5, 0x28, 0x70, 0xc9, 0x9a, 0x55,
    0xfc, 0xd0, 0x62, 0x76, 0x1f, 0x83, 0xa4, 0xc3, 0x8b, 0x51, 0x82, 0x16, 0x01, 0xcd, 0x2b, 0xab,
    0x15, 0xff, 0xe6, 0x66, 0xe2, 0xed, 0x62, 0xa4, 0x28, 0x0c, 0xfe, 0x1d, 0xe5, 0xc2, 0xa2, 0x38,
    0xd6, 0x89, 0x31, 0x32, 0x23, 0xd0, 0x07, 0x07, 0x2d, 0xbf, 0xa8, 0xa0, 0x66, 0xa4, 0x20, 0x72,
    0x60, 0x04, 0x86, 0x8f, 0xf1, 0x70, 0x3a, 0x56, 0x34, 0x8b, 0xd1, 0x06, 0xe9, 0x9c, 0xf7, 0xd2,
    0x48, 0xb6, 0x3f, 0x0f, 0x86, 0x04, 0xbc, 0xd0, 0xa3, 0x82, 0x01, 0x4d, 0x30, 0x82, 0x01, 0x49,
    0x30, 0x12, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x01, 0x01, 0xff, 0x04, 0x08, 0x30, 0x06, 0x01, 0x01,
    0xff, 0x02, 0x01, 0x00, 0x30, 0x0e, 0x06, 0x03, 0x55, 0x1d, 0x0f, 0x01, 0x01, 0xff, 0x04, 0x04,
    0x03, 0x02, 0x02, 0x04, 0x30, 0x16, 0x06, 0x06, 0x67, 0x81, 0x05, 0x05, 0x04, 0x04, 0x04, 0x0c,
    0x30, 0x0a, 0x04, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x30, 0x81, 0xca, 0x06,
    0x06, 0x67, 0x81, 0x05, 0x05, 0x04, 0x05, 0x04, 0x81, 0xbf, 0x30, 0x81, 0xbc, 0x30, 0x24, 0x80,
    0x08, 0x43, 0x61, 0x6c, 0x69, 0x70, 0x74, 0x72, 0x61, 0x81, 0x06, 0x44, 0x65, 0x76, 0x69, 0x63,
    0x65, 0x83, 0x02, 0x01, 0x07, 0x87, 0x05, 0x00, 0x80, 0x00, 0x00, 0x00, 0x8a, 0x05, 0x00, 0x80,
    0x00, 0x00, 0x0b, 0x30, 0x81, 0x93, 0x80, 0x08, 0x43, 0x61, 0x6c, 0x69, 0x70, 0x74, 0x72, 0x61,
    0x81, 0x03, 0x46, 0x4d, 0x43, 0x83, 0x02, 0x01, 0x09, 0xa6, 0x7e, 0x30, 0x3d, 0x06, 0x09, 0x60,
    0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x04, 0x30, 0x06, 0xd8, 0xf3, 0x54, 0x3a, 0xd2,
    0x68, 0xd8, 0xcb, 0xb4, 0x22, 0x07, 0x04, 0xec, 0x47, 0xc9, 0x33, 0x01, 0xfe, 0xd8, 0xcb, 0xae,
    0x27, 0x40, 0xbf, 0x94, 0x4b, 0x0b, 0x84, 0x88, 0x2c, 0x0c, 0xf2, 0xdb, 0x4f, 0x76, 0x5b, 0x67,
    0x14, 0x53, 0xa2, 0x56, 0xde, 0x5d, 0xa4, 0x90, 0xd7, 0xc8, 0x30, 0x3d, 0x06, 0x09, 0x60, 0x86,
    0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x04, 0x30, 0x42, 0x12, 0x75, 0xa8, 0x7a, 0x71, 0xac,
    0xf4, 0x34, 0xb4, 0xf1, 0x07, 0x6a, 0xcd, 0xd6, 0x83, 0x77, 0xd0, 0xa3, 0x15, 0xf9, 0xe2, 0xa2,
    0x9b, 0x26, 0xb3, 0x98, 0x91, 0x3e, 0x89, 0xff, 0x33, 0x00, 0x6c, 0x10, 0xdc, 0xc4, 0xf1, 0xbd,
    0x74, 0x67, 0xf1, 0xe2, 0xc4, 0x1b, 0x0a, 0x89, 0x3a, 0x30, 0x1d, 0x06, 0x03, 0x55, 0x1d, 0x0e,
    0x04, 0x16, 0x04, 0x14, 0x82, 0xb0, 0xfb, 0xb6, 0x60, 0x59, 0xb8, 0x54, 0x55, 0xea, 0xc8, 0x95,
    0x65, 0xc0, 0xc3, 0x7b, 0x67, 0x0f, 0xb1, 0x87, 0x30, 0x1f, 0x06, 0x03, 0x55, 0x1d, 0x23, 0x04,
    0x18, 0x30, 0x16, 0x80, 0x14, 0x21, 0xee, 0xef, 0x9a, 0x4c, 0x61, 0xd4, 0xb9, 0xe3, 0xd9, 0x4b,
    0xea, 0x46, 0xf9, 0xa1, 0x2a, 0xc6, 0x88, 0x7c, 0xe2,
];

const FAKE_FMC_ALIAS_PUB_KEY: Ecc384PubKey = Ecc384PubKey {
    x: Array4xN([
        0xD74C25C3, 0x71BB0F48, 0x9B1E202C, 0x6757CF47, 0xD282C528, 0x70C99A55, 0xFCD06276,
        0x1F83A4C3, 0x8B518216, 0x01CD2BAB, 0x15FFE666, 0xE2ED62A4,
    ]),
    y: Array4xN([
        0x280CFE1D, 0xE5C2A238, 0xD6893132, 0x23D00707, 0x2DBFA8A0, 0x66A42072, 0x6004868F,
        0xF1703A56, 0x348BD106, 0xE99CF7D2, 0x48B63F0F, 0x8604BCD0,
    ]),
};
const FAKE_FMC_ALIAS_SIG: Ecc384Signature = Ecc384Signature {
    r: Array4xN([
        0x5BA93B47, 0x21912443, 0x9475C1EB, 0xD4029FA6, 0x3C81D138, 0xE8B7F4A5, 0x55F39BF2,
        0x2233DD74, 0x93CE6FA8, 0xDCF70CD7, 0x00581DFF, 0x12427FF5,
    ]),
    s: Array4xN([
        0xFFA8D041, 0x8028799F, 0x44980CC1, 0xF6ECCF87, 0x638BDBF2, 0x5FF08EA9, 0xC9A3AFC7,
        0x33B4A123, 0x91D88E63, 0x6963B0F4, 0x1CABA7AD, 0x9585ACA5,
    ]),
};

pub struct FakeRomFlow {}

impl FakeRomFlow {
    /// Execute ROM Flows based on reset reason
    ///
    /// # Arguments
    ///
    /// * `env` - ROM Environment
    #[inline(never)]
    pub fn run(env: &mut RomEnv) -> CaliptraResult<()> {
        let reset_reason = env.soc_ifc.reset_reason();
        match reset_reason {
            // Cold Reset Flow
            ResetReason::ColdReset => {
                cprintln!("[fake-rom-cold-reset] ++");
                report_boot_status(ColdResetStarted.into());

                // Zeroize the key vault in the fake ROM flow
                unsafe { KeyVault::zeroize() };

                env.soc_ifc.flow_status_set_ready_for_firmware();

                fht::initialize_fht(env);

                // SKIP Execute IDEVID layer
                // LDEVID cert
                copy_canned_ldev_cert(env)?;

                // Unlock the SHA Acc by creating a SHA Acc operation and dropping it.
                // In real ROM, this is done as part of executing the SHA-ACC KAT.
                let sha_op = env
                    .sha2_512_384_acc
                    .try_start_operation(ShaAccLockState::AssumedLocked)?
                    .unwrap();
                drop(sha_op);

                // Download and validate firmware.
                _ = FirmwareProcessor::process(env)?;

                // FMC Alias Cert
                copy_canned_fmc_alias_cert(env)?;

                cprintln!("[fake-rom-cold-reset] --");
                report_boot_status(ColdResetComplete.into());

                Ok(())
            }

            // Warm Reset Flow
            ResetReason::WarmReset => warm_reset::WarmResetFlow::run(env),

            // Update Reset Flow
            ResetReason::UpdateReset => update_reset::UpdateResetFlow::run(env),

            // Unknown/Spurious Reset Flow
            ResetReason::Unknown => Err(CaliptraError::ROM_UNKNOWN_RESET_FLOW),
        }
    }
}

pub fn copy_canned_ldev_cert(env: &mut RomEnv) -> CaliptraResult<()> {
    // Store signature
    env.data_vault.set_ldev_dice_signature(&FAKE_LDEV_SIG);

    // Store pub key
    env.data_vault.set_ldev_dice_pub_key(&FAKE_LDEV_PUB_KEY);

    // Copy TBS to DCCM
    let tbs = &FAKE_LDEV_TBS;
    env.persistent_data.get_mut().fht.ldevid_tbs_size = u16::try_from(tbs.len()).unwrap();
    let Some(dst) = env.persistent_data.get_mut().ldevid_tbs.get_mut(..tbs.len()) else {
        return Err(CaliptraError::ROM_GLOBAL_UNSUPPORTED_LDEVID_TBS_SIZE);
    };
    dst.copy_from_slice(tbs);

    Ok(())
}

pub fn copy_canned_fmc_alias_cert(env: &mut RomEnv) -> CaliptraResult<()> {
    // Store signature
    env.data_vault.set_fmc_dice_signature(&FAKE_FMC_ALIAS_SIG);

    // Store pub key
    env.data_vault.set_fmc_pub_key(&FAKE_FMC_ALIAS_PUB_KEY);

    // Copy TBS to DCCM
    let tbs = &FAKE_FMC_ALIAS_TBS;
    env.persistent_data.get_mut().fht.fmcalias_tbs_size = u16::try_from(tbs.len()).unwrap();
    let Some(dst) = env.persistent_data.get_mut().fmcalias_tbs.get_mut(..tbs.len()) else {
        return Err(CaliptraError::ROM_GLOBAL_UNSUPPORTED_FMCALIAS_TBS_SIZE);
    };
    dst.copy_from_slice(tbs);
    Ok(())
}
