use incrementalmerkletree::Address;
use secrecy::{ExposeSecret, SecretVec};
use shardtree::{error::ShardTreeError, store::memory::MemoryShardStore, ShardTree};
use std::{
    cmp::Ordering,
    collections::{BTreeMap, HashMap},
    convert::Infallible,
    num::NonZeroU32,
};
use zcash_keys::keys::{AddressGenerationError, DerivationError};
use zip32::{DiversifierIndex, Scope};

use zcash_primitives::{
    block::BlockHash,
    consensus::{BlockHeight, Network},
    memo::Memo,
    transaction::{components::amount::NonNegativeAmount, Transaction, TxId},
    zip32::AccountId,
};

use crate::{
    address::UnifiedAddress,
    keys::{UnifiedAddressRequest, UnifiedFullViewingKey, UnifiedSpendingKey},
    wallet::{NoteId, WalletTransparentOutput, WalletTx},
};

use super::{
    chain::CommitmentTreeRoot, scanning::ScanRange, AccountBirthday, BlockMetadata,
    DecryptedTransaction, NullifierQuery, ScannedBlock, SentTransaction, WalletCommitmentTrees,
    WalletRead, WalletSummary, WalletWrite, SAPLING_SHARD_HEIGHT,
};

#[cfg(feature = "transparent-inputs")]
use {crate::wallet::TransparentAddressMetadata, zcash_primitives::legacy::TransparentAddress};

#[cfg(feature = "orchard")]
use super::ORCHARD_SHARD_HEIGHT;

pub struct MemoryWalletBlock {
    pub height: BlockHeight,
    pub hash: BlockHash,
    pub block_time: u32,
    // Just the transactions that involve an account in this wallet
    pub transactions: HashMap<TxId, WalletTx<u32>>,
}

impl PartialEq for MemoryWalletBlock {
    fn eq(&self, other: &Self) -> bool {
        (self.height, self.block_time) == (other.height, other.block_time)
    }
}

impl Eq for MemoryWalletBlock {}

impl PartialOrd for MemoryWalletBlock {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some((self.height, self.block_time).cmp(&(other.height, other.block_time)))
    }
}

impl Ord for MemoryWalletBlock {
    fn cmp(&self, other: &Self) -> Ordering {
        (self.height, self.block_time).cmp(&(other.height, other.block_time))
    }
}

pub struct MemoryWalletAccount {
    account_id: AccountId,
    ufvk: UnifiedFullViewingKey,
    birthday: AccountBirthday,
    addresses: BTreeMap<DiversifierIndex, UnifiedAddressRequest>,
}

pub struct MemoryWalletDb {
    pub network: Network,
    pub blocks: BTreeMap<BlockHeight, MemoryWalletBlock>,
    pub tx_idx: HashMap<TxId, BlockHeight>,
    pub accounts: BTreeMap<u32, MemoryWalletAccount>,
    pub sapling_spends: HashMap<sapling::Nullifier, (TxId, bool)>,
    #[cfg(feature = "orchard")]
    pub orchard_spends: HashMap<orchard::note::Nullifier, (TxId, bool)>,
    pub sapling_tree: ShardTree<
        MemoryShardStore<sapling::Node, BlockHeight>,
        { SAPLING_SHARD_HEIGHT * 2 },
        SAPLING_SHARD_HEIGHT,
    >,
    #[cfg(feature = "orchard")]
    pub orchard_tree: ShardTree<
        MemoryShardStore<orchard::tree::MerkleHashOrchard, BlockHeight>,
        { ORCHARD_SHARD_HEIGHT * 2 },
        ORCHARD_SHARD_HEIGHT,
    >,
}

#[derive(Debug)]
pub enum AddressGenerationErrors {
    DerivationError,
    AddressGenerationError,
}

#[derive(Debug)]
pub enum MemoryWalletError {
    AccountUnknown(u32),
    MemoDecryptionError,
    AddressGeneration(AddressGenerationErrors),
    ScanRequired,
}

impl From<DerivationError> for MemoryWalletError {
    fn from(value: DerivationError) -> Self {
        MemoryWalletError::AddressGeneration(AddressGenerationErrors::DerivationError)
    }
}

impl From<AddressGenerationError> for MemoryWalletError {
    fn from(value: AddressGenerationError) -> Self {
        MemoryWalletError::AddressGeneration(AddressGenerationErrors::AddressGenerationError)
    }
}

impl WalletRead for MemoryWalletDb {
    type Error = MemoryWalletError;
    type AccountId = u32;

    fn chain_height(&self) -> Result<Option<BlockHeight>, Self::Error> {
        self.blocks
            .iter()
            .last()
            .map(|(height, _)| *height)
            .map_or(Ok(None), |h| Ok(Some(h)))
    }

    fn block_metadata(&self, _height: BlockHeight) -> Result<Option<BlockMetadata>, Self::Error> {
        Ok(None)
    }

    fn block_fully_scanned(&self) -> Result<Option<BlockMetadata>, Self::Error> {
        Ok(None)
    }

    fn block_max_scanned(&self) -> Result<Option<BlockMetadata>, Self::Error> {
        let last_inserted_block = self.blocks.iter().last();
        let block_meta_data = last_inserted_block.map(|(height, block)| BlockMetadata {
            block_height: *height,
            block_hash: block.hash,
            sapling_tree_size: None,
        });

        Ok(block_meta_data)
    }

    fn suggest_scan_ranges(&self) -> Result<Vec<ScanRange>, Self::Error> {
        Ok(vec![])
    }

    fn get_target_and_anchor_heights(
        &self,
        _min_confirmations: NonZeroU32,
    ) -> Result<Option<(BlockHeight, BlockHeight)>, Self::Error> {
        Ok(None)
    }

    fn get_min_unspent_height(&self) -> Result<Option<BlockHeight>, Self::Error> {
        Ok(None)
    }

    fn get_block_hash(&self, block_height: BlockHeight) -> Result<Option<BlockHash>, Self::Error> {
        Ok(self.blocks.iter().find_map(|b| {
            if b.0 == &block_height {
                Some(b.1.hash)
            } else {
                None
            }
        }))
    }

    fn get_max_height_hash(&self) -> Result<Option<(BlockHeight, BlockHash)>, Self::Error> {
        Ok(None)
    }

    fn get_tx_height(&self, _txid: TxId) -> Result<Option<BlockHeight>, Self::Error> {
        Ok(None)
    }

    fn get_wallet_birthday(&self) -> Result<Option<BlockHeight>, Self::Error> {
        Ok(None)
    }

    fn get_account_birthday(&self, _account: Self::AccountId) -> Result<BlockHeight, Self::Error> {
        Err(MemoryWalletError::AccountUnknown(_account))
    }

    fn get_current_address(
        &self,
        account: Self::AccountId,
    ) -> Result<Option<UnifiedAddress>, Self::Error> {
        self.accounts
            .get(&account)
            .map(|account| {
                account
                    .ufvk
                    .default_address(
                        UnifiedAddressRequest::all()
                            .expect("At least one protocol should be enabled."),
                    )
                    .map(|(addr, _)| addr)
            })
            .transpose()
            .map_err(|e| e.into())
    }

    fn get_unified_full_viewing_keys(
        &self,
    ) -> Result<HashMap<Self::AccountId, UnifiedFullViewingKey>, Self::Error> {
        Ok(HashMap::new())
    }

    fn get_account_for_ufvk(
        &self,
        ufvk: &UnifiedFullViewingKey,
    ) -> Result<Option<Self::AccountId>, Self::Error> {
        let ufvk_req =
            UnifiedAddressRequest::all().expect("At least one protocol should be enabled");
        Ok(self.accounts.iter().find_map(|(id, acct)| {
            if acct.ufvk.default_address(ufvk_req).unwrap()
                == ufvk.default_address(ufvk_req).unwrap()
            {
                Some(*id)
            } else {
                None
            }
        }))
    }

    fn get_wallet_summary(
        &self,
        _min_confirmations: u32,
    ) -> Result<Option<WalletSummary<Self::AccountId>>, Self::Error> {
        Ok(None)
    }
    //        fn get_balance_at(
    //            &self,
    //            account: AccountId,
    //            height: BlockHeight,
    //        ) -> Result<Amount, Self::Error> {
    //            let mut received_amounts: HashMap<Nullifier, Amount> = HashMap::new();
    //            Ok(self.blocks.iter().filter(|b| b.height <= height).fold(
    //                Amount::zero(),
    //                |acc, block| {
    //                    block.transactions.values().fold(acc, |acc, wallet_tx| {
    //                        // add to our balance when we receive an output
    //                        let total_received = wallet_tx
    //                            .shielded_outputs
    //                            .iter()
    //                            .filter(|s| s.account == account)
    //                            .fold(acc, |acc, o| {
    //                                let nf = o.note.nf(
    //                                    &self.accounts.get(&account).unwrap().fvk.vk,
    //                                    o.witness.position() as u64,
    //                                );
    //                                let amount = Amount::from_u64(o.note.value).unwrap();
    //
    //                                // cache received amounts
    //                                received_amounts.insert(nf, amount);
    //                                acc + amount
    //                            });
    //
    //                        // subtract the previously cached received amount when we observe
    //                        // a spend of its nullifier
    //                        wallet_tx
    //                            .shielded_spends
    //                            .iter()
    //                            .filter(|s| {
    //                                self.spentness
    //                                    .get(&s.nf)
    //                                    .filter(|(_, spent)| *spent)
    //                                    .is_some()
    //                            })
    //                            .fold(total_received, |acc, s| {
    //                                received_amounts.get(&s.nf).map_or(acc, |amt| acc - *amt)
    //                            })
    //                    })
    //                },
    //            ))
    //        }

    fn get_memo(&self, id_note: NoteId) -> Result<Option<Memo>, Self::Error> {
        /*
        self.blocks
            .iter()
            .find_map(|(_, b)| {
                b.transactions.iter().find_map(|(txid, tx)| {
                    if *txid == *id_note.txid() {
                        tx.sapling_outputs().iter().find_map(|wso| {
                            if wso.index() == id_note.output_index().into() {
                                wso. memo.clone().and_then(|m| m.to_utf8())
                            } else {
                                None
                            }
                        })
                    } else {
                        None
                    }
                })
            })
            .transpose()
            .map_err(|_| MemoryWalletError::MemoDecryptionError)
        */
        Err(MemoryWalletError::MemoDecryptionError)
    }

    fn get_transaction(&self, _id_tx: TxId) -> Result<Transaction, Self::Error> {
        Err(MemoryWalletError::ScanRequired) // wrong error but we'll fix it later.
    }

    fn get_sapling_nullifiers(
        &self,
        _query: NullifierQuery,
    ) -> Result<Vec<(Self::AccountId, sapling::Nullifier)>, Self::Error> {
        Ok(Vec::new())
    }

    #[cfg(feature = "orchard")]
    fn get_orchard_nullifiers(
        &self,
        _query: NullifierQuery,
    ) -> Result<Vec<(Self::AccountId, orchard::note::Nullifier)>, Self::Error> {
        Ok(Vec::new())
    }

    #[cfg(feature = "transparent-inputs")]
    fn get_transparent_receivers(
        &self,
        _account: Self::AccountId,
    ) -> Result<HashMap<TransparentAddress, Option<TransparentAddressMetadata>>, Self::Error> {
        Ok(HashMap::new())
    }

    #[cfg(feature = "transparent-inputs")]
    fn get_transparent_balances(
        &self,
        _account: Self::AccountId,
        _max_height: BlockHeight,
    ) -> Result<HashMap<TransparentAddress, NonNegativeAmount>, Self::Error> {
        Ok(HashMap::new())
    }

    fn get_account_ids(&self) -> Result<Vec<Self::AccountId>, Self::Error> {
        Ok(Vec::new())
    }

    fn validate_seed(
        &self,
        account_id: Self::AccountId,
        seed: &SecretVec<u8>,
    ) -> Result<bool, Self::Error> {
        todo!()
    }
}

impl WalletWrite for MemoryWalletDb {
    type UtxoRef = u32;

    fn create_account(
        &mut self,
        seed: &SecretVec<u8>,
        birthday: AccountBirthday,
    ) -> Result<(Self::AccountId, UnifiedSpendingKey), Self::Error> {
        let account_id_number = self.accounts.last_key_value().map_or(0, |(id, _)| id + 1);
        let account_id = AccountId::try_from(account_id_number)
            .map_err(|_| MemoryWalletError::AccountUnknown(account_id_number))?;
        let usk = UnifiedSpendingKey::from_seed(&self.network, seed.expose_secret(), account_id)
            .map_err(|e| {
                MemoryWalletError::AddressGeneration(AddressGenerationErrors::DerivationError)
            })?;
        let ufvk = usk.to_unified_full_viewing_key();
        self.accounts.insert(
            account_id_number,
            MemoryWalletAccount {
                account_id,
                ufvk,
                birthday,
                addresses: BTreeMap::new(),
            },
        );

        Ok((account_id_number, usk))
    }

    fn get_next_available_address(
        &mut self,
        account: Self::AccountId,
        request: UnifiedAddressRequest,
    ) -> Result<Option<UnifiedAddress>, Self::Error> {
        Err(MemoryWalletError::ScanRequired)
        /*
        self.accounts
            .get(&account)
            .map(|acct| acct.addresses.last_key_value())
        */
    }

    #[allow(clippy::type_complexity)]
    fn put_blocks(
        &mut self,
        blocks: Vec<ScannedBlock<Self::AccountId>>,
    ) -> Result<(), Self::Error> {
        let mut tx_idx = HashMap::new();

        for block in blocks {
            let transactions: HashMap<TxId, WalletTx<u32>> = HashMap::new();
            for transaction in block.transactions {
                // Fix this: we are assuming that the account is 0 among other things
                transaction
                    .sapling_outputs()
                    .iter()
                    .map(|o| {
                        o.note().nf(
                            &self
                                .accounts
                                .get(&0)
                                .unwrap()
                                .ufvk
                                .sapling()
                                .unwrap()
                                .to_nk(Scope::External),
                            o.note_commitment_tree_position().into(),
                        )
                    })
                    .fold(0, |_, nullifier| {
                        self.sapling_spends
                            .insert(nullifier, (transaction.txid(), true));
                        1
                    });
                let txid = transaction.txid();
                self.tx_idx.insert(transaction.txid(), block.block_height);
                tx_idx.insert(txid, block.block_height);
            }

            let memory_block = MemoryWalletBlock {
                height: block.block_height,
                hash: block.block_hash,
                block_time: block.block_time,
                transactions,
            };

            self.blocks.insert(block.block_height, memory_block);
        }

        Ok(())
    }

    fn update_chain_tip(&mut self, _tip_height: BlockHeight) -> Result<(), Self::Error> {
        // We are using the last inserted block height as the tip so we don't need to do anything here.
        // If we want to update the tip we have to add a new field to `MemoryWalletDb` or change the height of the last block.
        Ok(())
    }

    fn store_decrypted_tx(
        &mut self,
        _received_tx: DecryptedTransaction<Self::AccountId>,
    ) -> Result<(), Self::Error> {
        Ok(())
    }

    fn store_sent_tx(
        &mut self,
        _sent_tx: &SentTransaction<Self::AccountId>,
    ) -> Result<(), Self::Error> {
        Ok(())
    }

    fn truncate_to_height(&mut self, _block_height: BlockHeight) -> Result<(), Self::Error> {
        Ok(())
    }

    /// Adds a transparent UTXO received by the wallet to the data store.
    fn put_received_transparent_utxo(
        &mut self,
        _output: &WalletTransparentOutput,
    ) -> Result<Self::UtxoRef, Self::Error> {
        Ok(0)
    }
}

impl WalletCommitmentTrees for MemoryWalletDb {
    type Error = Infallible;
    type SaplingShardStore<'a> = MemoryShardStore<sapling::Node, BlockHeight>;

    fn with_sapling_tree_mut<F, A, E>(&mut self, mut callback: F) -> Result<A, E>
    where
        for<'a> F: FnMut(
            &'a mut ShardTree<
                Self::SaplingShardStore<'a>,
                { sapling::NOTE_COMMITMENT_TREE_DEPTH },
                SAPLING_SHARD_HEIGHT,
            >,
        ) -> Result<A, E>,
        E: From<ShardTreeError<Infallible>>,
    {
        callback(&mut self.sapling_tree)
    }

    fn put_sapling_subtree_roots(
        &mut self,
        start_index: u64,
        roots: &[CommitmentTreeRoot<sapling::Node>],
    ) -> Result<(), ShardTreeError<Self::Error>> {
        self.with_sapling_tree_mut(|t| {
            for (root, i) in roots.iter().zip(0u64..) {
                let root_addr = Address::from_parts(SAPLING_SHARD_HEIGHT.into(), start_index + i);
                t.insert(root_addr, *root.root_hash())?;
            }
            Ok::<_, ShardTreeError<Self::Error>>(())
        })?;

        Ok(())
    }

    #[cfg(feature = "orchard")]
    type OrchardShardStore<'a> = MemoryShardStore<orchard::tree::MerkleHashOrchard, BlockHeight>;

    #[cfg(feature = "orchard")]
    fn with_orchard_tree_mut<F, A, E>(&mut self, mut callback: F) -> Result<A, E>
    where
        for<'a> F: FnMut(
            &'a mut ShardTree<
                Self::OrchardShardStore<'a>,
                { ORCHARD_SHARD_HEIGHT * 2 },
                ORCHARD_SHARD_HEIGHT,
            >,
        ) -> Result<A, E>,
        E: From<ShardTreeError<Self::Error>>,
    {
        callback(&mut self.orchard_tree)
    }

    /// Adds a sequence of note commitment tree subtree roots to the data store.
    #[cfg(feature = "orchard")]
    fn put_orchard_subtree_roots(
        &mut self,
        start_index: u64,
        roots: &[CommitmentTreeRoot<orchard::tree::MerkleHashOrchard>],
    ) -> Result<(), ShardTreeError<Self::Error>> {
        self.with_orchard_tree_mut(|t| {
            for (root, i) in roots.iter().zip(0u64..) {
                let root_addr = Address::from_parts(ORCHARD_SHARD_HEIGHT.into(), start_index + i);
                t.insert(root_addr, *root.root_hash())?;
            }
            Ok::<_, ShardTreeError<Self::Error>>(())
        })?;

        Ok(())
    }
}
