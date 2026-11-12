// SPDX-License-Identifier: MIT

//! Generic netlink controller implementation
//!
//! This module provides the definition of the controller packet.
//! It also serves as an example for creating a generic family.

mod attr;
mod mcast;
mod message;
mod oppolicy;
mod ops;
mod policy;

pub use self::attr::GenlCtrlAttr;
pub use self::mcast::{GenlCtrlMcastGroup, GenlCtrlMcastGroupSet};
pub use self::message::{GenlCtrlCmd, GenlCtrlMessage};
pub use self::oppolicy::{GenlCtrlOpPolicy, GenlCtrlOpPolicyIndex};
pub use self::ops::{GenlCtrlOp, GenlCtrlOpFlags, GenlCtrlOpSet};
pub use self::policy::{
    GenlCtrlPolicy, GenlCtrlPolicyByteOrder, GenlCtrlPolicyEntry,
    GenlCtrlPolicySet, GenlCtrlPolicyType,
};
