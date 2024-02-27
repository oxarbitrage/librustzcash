//! Structs for handling supported address types.

use zcash_address::{
    unified::{self, Container, Encoding, Typecode},
    ConversionError, Network, ToAddress, TryFromRawAddress, ZcashAddress,
};
use zcash_primitives::{consensus, legacy::TransparentAddress};

#[cfg(feature = "sapling")]
use sapling::PaymentAddress;

/// A Unified Address.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnifiedAddress {
    #[cfg(feature = "orchard")]
    orchard: Option<orchard::Address>,
    #[cfg(feature = "sapling")]
    sapling: Option<PaymentAddress>,
    transparent: Option<TransparentAddress>,
    unknown: Vec<(u32, Vec<u8>)>,
}

impl TryFrom<unified::Address> for UnifiedAddress {
    type Error = &'static str;

    fn try_from(ua: unified::Address) -> Result<Self, Self::Error> {
        #[cfg(feature = "orchard")]
        let mut orchard = None;
        #[cfg(feature = "sapling")]
        let mut sapling = None;
        let mut transparent = None;

        let mut unknown: Vec<(u32, Vec<u8>)> = vec![];

        // We can use as-parsed order here for efficiency, because we're breaking out the
        // receivers we support from the unknown receivers.
        for item in ua.items_as_parsed() {
            match item {
                unified::Receiver::Orchard(data) => {
                    #[cfg(feature = "orchard")]
                    {
                        orchard = Some(
                            Option::from(orchard::Address::from_raw_address_bytes(data))
                                .ok_or("Invalid Orchard receiver in Unified Address")?,
                        );
                    }
                    #[cfg(not(feature = "orchard"))]
                    {
                        unknown.push((unified::Typecode::Orchard.into(), data.to_vec()));
                    }
                }

                unified::Receiver::Sapling(data) => {
                    #[cfg(feature = "sapling")]
                    {
                        sapling = Some(
                            PaymentAddress::from_bytes(data)
                                .ok_or("Invalid Sapling receiver in Unified Address")?,
                        );
                    }
                    #[cfg(not(feature = "sapling"))]
                    {
                        unknown.push((unified::Typecode::Sapling.into(), data.to_vec()));
                    }
                }

                unified::Receiver::P2pkh(data) => {
                    transparent = Some(TransparentAddress::PublicKeyHash(*data));
                }

                unified::Receiver::P2sh(data) => {
                    transparent = Some(TransparentAddress::ScriptHash(*data));
                }

                unified::Receiver::Unknown { typecode, data } => {
                    unknown.push((*typecode, data.clone()));
                }
            }
        }

        Ok(Self {
            #[cfg(feature = "orchard")]
            orchard,
            #[cfg(feature = "sapling")]
            sapling,
            transparent,
            unknown,
        })
    }
}

impl UnifiedAddress {
    /// Constructs a Unified Address from a given set of receivers.
    ///
    /// Returns `None` if the receivers would produce an invalid Unified Address (namely,
    /// if no shielded receiver is provided).
    pub fn from_receivers(
        #[cfg(feature = "orchard")] orchard: Option<orchard::Address>,
        #[cfg(feature = "sapling")] sapling: Option<PaymentAddress>,
        transparent: Option<TransparentAddress>,
        // TODO: Add handling for address metadata items.
    ) -> Option<Self> {
        #[cfg(feature = "orchard")]
        let has_orchard = orchard.is_some();
        #[cfg(not(feature = "orchard"))]
        let has_orchard = false;

        #[cfg(feature = "sapling")]
        let has_sapling = sapling.is_some();
        #[cfg(not(feature = "sapling"))]
        let has_sapling = false;

        if has_orchard || has_sapling {
            Some(Self {
                #[cfg(feature = "orchard")]
                orchard,
                #[cfg(feature = "sapling")]
                sapling,
                transparent,
                unknown: vec![],
            })
        } else {
            // UAs require at least one shielded receiver.
            None
        }
    }

    /// Returns whether this address has an Orchard receiver.
    ///
    /// This method is available irrespective of whether the `orchard` feature flag is enabled.
    pub fn has_orchard(&self) -> bool {
        #[cfg(not(feature = "orchard"))]
        return false;
        #[cfg(feature = "orchard")]
        return self.orchard.is_some();
    }

    /// Returns the Orchard receiver within this Unified Address, if any.
    #[cfg(feature = "orchard")]
    pub fn orchard(&self) -> Option<&orchard::Address> {
        self.orchard.as_ref()
    }

    /// Returns whether this address has a Sapling receiver.
    pub fn has_sapling(&self) -> bool {
        self.sapling.is_some()
    }

    /// Returns the Sapling receiver within this Unified Address, if any.
    #[cfg(feature = "sapling")]
    pub fn sapling(&self) -> Option<&PaymentAddress> {
        self.sapling.as_ref()
    }

    /// Returns whether this address has a Transparent receiver.
    pub fn has_transparent(&self) -> bool {
        self.transparent.is_some()
    }

    /// Returns the transparent receiver within this Unified Address, if any.
    pub fn transparent(&self) -> Option<&TransparentAddress> {
        self.transparent.as_ref()
    }

    /// Returns the set of unknown receivers of the unified address.
    pub fn unknown(&self) -> &[(u32, Vec<u8>)] {
        &self.unknown
    }

    fn to_address(&self, net: Network) -> ZcashAddress {
        let items = self
            .unknown
            .iter()
            .map(|(typecode, data)| unified::Receiver::Unknown {
                typecode: *typecode,
                data: data.clone(),
            });

        #[cfg(feature = "orchard")]
        let items = items.chain(
            self.orchard
                .as_ref()
                .map(|addr| addr.to_raw_address_bytes())
                .map(unified::Receiver::Orchard),
        );

        #[cfg(feature = "sapling")]
        let items = items.chain(
            self.sapling
                .as_ref()
                .map(|pa| pa.to_bytes())
                .map(unified::Receiver::Sapling),
        );

        let items = items.chain(self.transparent.as_ref().map(|taddr| match taddr {
            TransparentAddress::PublicKeyHash(data) => unified::Receiver::P2pkh(*data),
            TransparentAddress::ScriptHash(data) => unified::Receiver::P2sh(*data),
        }));

        let ua = unified::Address::try_from_items(items.collect())
            .expect("UnifiedAddress should only be constructed safely");
        ZcashAddress::from_unified(net, ua)
    }

    /// Returns the string encoding of this `UnifiedAddress` for the given network.
    pub fn encode<P: consensus::Parameters>(&self, params: &P) -> String {
        self.to_address(params.address_network().expect("Unrecognized network"))
            .to_string()
    }

    /// Returns the set of receiver typecodes.
    pub fn receiver_types(&self) -> Vec<Typecode> {
        let result = std::iter::empty();
        #[cfg(feature = "orchard")]
        let result = result.chain(self.orchard.map(|_| Typecode::Orchard));
        let result = result.chain(self.sapling.map(|_| Typecode::Sapling));
        let result = result.chain(self.transparent.map(|taddr| match taddr {
            TransparentAddress::PublicKeyHash(_) => Typecode::P2pkh,
            TransparentAddress::ScriptHash(_) => Typecode::P2sh,
        }));
        let result = result.chain(
            self.unknown()
                .iter()
                .map(|(typecode, _)| Typecode::Unknown(*typecode)),
        );
        result.collect()
    }
}

/// An address that funds can be sent to.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Address {
    #[cfg(feature = "sapling")]
    Sapling(PaymentAddress),
    Transparent(TransparentAddress),
    Unified(UnifiedAddress),
}

#[cfg(feature = "sapling")]
impl From<PaymentAddress> for Address {
    fn from(addr: PaymentAddress) -> Self {
        Address::Sapling(addr)
    }
}

impl From<TransparentAddress> for Address {
    fn from(addr: TransparentAddress) -> Self {
        Address::Transparent(addr)
    }
}

impl From<UnifiedAddress> for Address {
    fn from(addr: UnifiedAddress) -> Self {
        Address::Unified(addr)
    }
}

impl TryFromRawAddress for Address {
    type Error = &'static str;

    #[cfg(feature = "sapling")]
    fn try_from_raw_sapling(data: [u8; 43]) -> Result<Self, ConversionError<Self::Error>> {
        let pa = PaymentAddress::from_bytes(&data).ok_or("Invalid Sapling payment address")?;
        Ok(pa.into())
    }

    fn try_from_raw_unified(
        ua: zcash_address::unified::Address,
    ) -> Result<Self, ConversionError<Self::Error>> {
        UnifiedAddress::try_from(ua)
            .map_err(ConversionError::User)
            .map(Address::from)
    }

    fn try_from_raw_transparent_p2pkh(
        data: [u8; 20],
    ) -> Result<Self, ConversionError<Self::Error>> {
        Ok(TransparentAddress::PublicKeyHash(data).into())
    }

    fn try_from_raw_transparent_p2sh(data: [u8; 20]) -> Result<Self, ConversionError<Self::Error>> {
        Ok(TransparentAddress::ScriptHash(data).into())
    }
}

impl Address {
    pub fn decode<P: consensus::Parameters>(params: &P, s: &str) -> Option<Self> {
        let addr = ZcashAddress::try_from_encoded(s).ok()?;
        addr.convert_if_network(params.address_network().expect("Unrecognized network"))
            .ok()
    }

    pub fn encode<P: consensus::Parameters>(&self, params: &P) -> String {
        let net = params.address_network().expect("Unrecognized network");

        match self {
            #[cfg(feature = "sapling")]
            Address::Sapling(pa) => ZcashAddress::from_sapling(net, pa.to_bytes()),
            Address::Transparent(addr) => match addr {
                TransparentAddress::PublicKeyHash(data) => {
                    ZcashAddress::from_transparent_p2pkh(net, *data)
                }
                TransparentAddress::ScriptHash(data) => {
                    ZcashAddress::from_transparent_p2sh(net, *data)
                }
            },
            Address::Unified(ua) => ua.to_address(net),
        }
        .to_string()
    }
}

#[cfg(any(test, feature = "test-dependencies"))]
pub mod testing {
    use proptest::prelude::*;
    use zcash_primitives::consensus::Network;

    use crate::keys::{testing::arb_unified_spending_key, UnifiedAddressRequest};

    use super::{Address, UnifiedAddress};

    #[cfg(feature = "sapling")]
    use sapling::testing::arb_payment_address;
    use zcash_primitives::legacy::testing::arb_transparent_addr;

    pub fn arb_unified_addr(
        params: Network,
        request: UnifiedAddressRequest,
    ) -> impl Strategy<Value = UnifiedAddress> {
        arb_unified_spending_key(params).prop_map(move |k| k.default_address(request).0)
    }

    #[cfg(feature = "sapling")]
    pub fn arb_addr(request: UnifiedAddressRequest) -> impl Strategy<Value = Address> {
        prop_oneof![
            arb_payment_address().prop_map(Address::Sapling),
            arb_transparent_addr().prop_map(Address::Transparent),
            arb_unified_addr(Network::TestNetwork, request).prop_map(Address::Unified),
        ]
    }

    #[cfg(not(feature = "sapling"))]
    pub fn arb_addr(request: UnifiedAddressRequest) -> impl Strategy<Value = Address> {
        return prop_oneof![
            arb_transparent_addr().prop_map(Address::Transparent),
            arb_unified_addr(Network::TestNetwork, request).prop_map(Address::Unified),
        ];
    }
}

#[cfg(test)]
mod tests {
    use zcash_address::test_vectors;
    use zcash_primitives::consensus::MAIN_NETWORK;

    use super::Address;

    #[cfg(feature = "sapling")]
    use crate::keys::sapling;

    #[cfg(any(feature = "orchard", feature = "sapling"))]
    use zcash_primitives::zip32::AccountId;

    #[cfg(any(feature = "orchard", feature = "sapling"))]
    use super::UnifiedAddress;

    #[test]
    #[cfg(any(feature = "orchard", feature = "sapling"))]
    fn ua_round_trip() {
        #[cfg(feature = "orchard")]
        let orchard = {
            let sk =
                orchard::keys::SpendingKey::from_zip32_seed(&[0; 32], 0, AccountId::ZERO).unwrap();
            let fvk = orchard::keys::FullViewingKey::from(&sk);
            Some(fvk.address_at(0u32, orchard::keys::Scope::External))
        };

        #[cfg(feature = "sapling")]
        let sapling = {
            let extsk = sapling::spending_key(&[0; 32], 0, AccountId::ZERO);
            let dfvk = extsk.to_diversifiable_full_viewing_key();
            Some(dfvk.default_address().1)
        };

        let transparent = None;

        #[cfg(all(feature = "orchard", feature = "sapling"))]
        let ua = UnifiedAddress::from_receivers(orchard, sapling, transparent).unwrap();

        #[cfg(all(not(feature = "orchard"), feature = "sapling"))]
        let ua = UnifiedAddress::from_receivers(sapling, transparent).unwrap();

        #[cfg(all(feature = "orchard", not(feature = "sapling")))]
        let ua = UnifiedAddress::from_receivers(orchard, transparent).unwrap();

        let addr = Address::Unified(ua);
        let addr_str = addr.encode(&MAIN_NETWORK);
        assert_eq!(Address::decode(&MAIN_NETWORK, &addr_str), Some(addr));
    }

    #[test]
    #[cfg(not(any(feature = "orchard", feature = "sapling")))]
    fn ua_round_trip() {
        let transparent = None;
        assert_eq!(UnifiedAddress::from_receivers(transparent), None)
    }

    #[test]
    fn ua_parsing() {
        for tv in test_vectors::UNIFIED {
            match Address::decode(&MAIN_NETWORK, tv.unified_addr) {
                Some(Address::Unified(_ua)) => {
                    assert_eq!(
                        _ua.transparent().is_some(),
                        tv.p2pkh_bytes.is_some() || tv.p2sh_bytes.is_some()
                    );
                    #[cfg(feature = "sapling")]
                    assert_eq!(_ua.sapling().is_some(), tv.sapling_raw_addr.is_some());
                    #[cfg(feature = "orchard")]
                    assert_eq!(_ua.orchard().is_some(), tv.orchard_raw_addr.is_some());
                }
                Some(_) => {
                    panic!(
                        "{} did not decode to a unified address value.",
                        tv.unified_addr
                    );
                }
                None => {
                    panic!(
                        "Failed to decode unified address from test vector: {}",
                        tv.unified_addr
                    );
                }
            }
        }
    }
}