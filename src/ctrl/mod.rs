// SPDX-License-Identifier: MIT

//! Generic netlink controller implementation
//!
//! This module provides the definition of the controller packet.
//! It also serves as an example for creating a generic family.

mod attr;
mod genl_ctrl;
mod mcast;
mod oppolicy;
mod ops;
mod policy;

pub use self::attr::GenlCtrlAttrs;
pub use self::genl_ctrl::{GenlCtrl, GenlCtrlCmd};
pub use self::mcast::McastGrpAttrs;
pub use self::oppolicy::{OppolicyAttr, OppolicyIndexAttr};
pub use self::ops::OpAttrs;
pub use self::policy::{
    AttributePolicyAttr, NlPolicyTypeAttrs, NlaType, PolicyAttr,
};
