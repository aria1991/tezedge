// Copyright (c) SimpleStaking, Viable Systems and Tezedge Contributors
// SPDX-License-Identifier: MIT

use crate::proposals::TickProposal;
use crate::{Effects, TezedgeState};
use tla_sm::Acceptor;

impl<'a, Efs> Acceptor<TickProposal<'a, Efs>> for TezedgeState
where
    Efs: Effects,
{
    fn accept(&mut self, proposal: TickProposal<'a, Efs>) {
        self.time += proposal.time_passed;
        self.periodic_react(proposal.effects);
    }
}
