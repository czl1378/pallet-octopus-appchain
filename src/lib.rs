#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use alloc::string::{String, ToString};

use frame_support::{
	decl_error, decl_event, decl_module, decl_storage, dispatch::DispatchResult, ensure,
	traits::{Get, OneSessionHandler},
};
use frame_system::{
	self as system, ensure_none,
	offchain::{
		CreateSignedTransaction, SendUnsignedTransaction, SignedPayload, Signer,
		SigningTypes, SendSignedTransaction
	},
};
use sp_core::crypto::KeyTypeId;
use sp_runtime::{
	offchain::{http, storage::StorageValueRef, Duration},
	traits::{Convert, IdentifyAccount, StaticLookup},
	transaction_validity::{
		InvalidTransaction, TransactionPriority, TransactionSource, TransactionValidity,
		ValidTransaction,
	},
	RuntimeDebug,
};
use sp_std::{prelude::*, vec::Vec};

use codec::{Decode, Encode};
use lite_json::json::{JsonValue, NumberValue};

#[cfg(test)]
mod mock;

#[cfg(test)]
mod tests;

/// Defines application identifier for crypto keys of this module.
///
/// Every module that deals with signatures needs to declare its unique identifier for
/// its crypto keys.
/// When offchain worker is signing transactions it's going to request keys of type
/// `KeyTypeId` from the keystore and use the ones it finds to sign the transaction.
/// The keys can be inserted manually via RPC (see `author_insertKey`).
pub const KEY_TYPE: KeyTypeId = KeyTypeId(*b"octo");

/// Based on the above `KeyTypeId` we need to generate a pallet-specific crypto type wrappers.
/// We can use from supported crypto kinds (`sr25519`, `ed25519` and `ecdsa`) and augment
/// the types with this pallet-specific identifier.
pub mod crypto {
	use super::KEY_TYPE;
	use sp_runtime::{
		app_crypto::{app_crypto, sr25519},
	};
	app_crypto!(sr25519, KEY_TYPE);

	pub type AuthorityId = Public;
}

/// Index of an appchain on the motherchain.
pub type ChainId = u32;

/// Motherchain type, currently only NEAR is supported.
pub enum MotherchainType {
	NEAR,
}

/// This pallet's configuration trait
pub trait Config: CreateSignedTransaction<Call<Self>> + pallet_session::Config + pallet_assets::Config {
	/// The identifier type for an offchain worker.
	type AppCrypto: frame_system::offchain::AppCrypto<Self::Public, Self::Signature>;

	/// The overarching event type.
	type Event: From<Event<Self>> + Into<<Self as frame_system::Config>::Event>;
	/// The overarching dispatch call type.
	type Call: From<Call<Self>>;
	
	/// The id assigned by motherchain to this appchain.
	type AppchainId: Get<ChainId>;

	/// The type of the motherchain, not in use.
	type Motherchain: Get<MotherchainType>;

	/// The name/address of the relay contract on the motherchain.
	const RELAY_CONTRACT_NAME: &'static [u8];

	/// The name/address of the locker contract on the motherchain.
    const LOCKER_CONTRACT_NAME: &'static [u8];

	/// A grace period after we send transaction.
	///
	/// To avoid sending too many transactions, we only attempt to send one
	/// every `GRACE_PERIOD` blocks. We use Local Storage to coordinate
	/// sending between distinct runs of this offchain worker.
	type GracePeriod: Get<Self::BlockNumber>;

	/// A configuration for base priority of unsigned transactions.
	///
	/// This is exposed so that it can be tuned for particular runtime, when
	/// multiple pallets send unsigned transactions.
	type UnsignedPriority: Get<TransactionPriority>;
}

/// Validator of appchain.
#[derive(Encode, Decode, Clone, PartialEq, Eq, RuntimeDebug)]
pub struct Validator<AccountId> {
	/// The validator's id.
	id: AccountId,
	/// The weight of this validator in motherchain's staking system.
	weight: u64,
}

/// The validator set of appchain.
#[derive(Encode, Decode, Clone, PartialEq, Eq, RuntimeDebug)]
pub struct ValidatorSet<AccountId> {
	/// The sequence number of this set on the motherchain.
	sequence_number: u32,
	/// Validators in this set.
	validators: Vec<Validator<AccountId>>,
}

/// The locked record of appchain
#[derive(Encode, Decode, Clone, PartialEq, Eq, RuntimeDebug)]
pub struct LockedEvent<AccountId> {
	sequence_number: u32,
	token_id: Vec<u8>,
    receiver_id: AccountId,
    amount: u64,
}

/// Payload used by this crate to hold validator set
/// data required to submit a transaction.
#[derive(Encode, Decode, Clone, PartialEq, Eq, RuntimeDebug)]
pub struct ValidatorSetPayload<Public, BlockNumber, AccountId> {
	public: Public,
	block_number: BlockNumber,
	val_set: ValidatorSet<AccountId>,
}

#[derive(Encode, Decode, Clone, PartialEq, Eq, RuntimeDebug)]
pub struct LockedEventsPayload<Public, BlockNumber, AccountId> {
    public: Public,
    block_number: BlockNumber,
    events: Vec<LockedEvent<AccountId>>,
}

impl<T: SigningTypes> SignedPayload<T>
	for ValidatorSetPayload<T::Public, T::BlockNumber, <T as frame_system::Config>::AccountId>
{
	fn public(&self) -> T::Public {
		self.public.clone()
	}
}

impl<T: SigningTypes> SignedPayload<T>
	for LockedEventsPayload<T::Public, T::BlockNumber, <T as frame_system::Config>::AccountId>
{
	fn public(&self) -> T::Public {
		self.public.clone()
	}
}

decl_storage! {
	trait Store for Module<T: Config> as OctopusAppchain {
		/// The current set of validators of this appchain.
		CurrentValidatorSet get(fn current_validator_set): Option<ValidatorSet<<T as frame_system::Config>::AccountId>>;
		/// A list of candidate validator sets.
		CandidateValidatorSets get(fn candidate_validator_sets): Vec<ValidatorSet<<T as frame_system::Config>::AccountId>>;
		/// A voting record for the index of CandidateValidatorSets.
		Voters get(fn voters):
		map hasher(twox_64_concat) u32
		=> Vec<Validator<<T as frame_system::Config>::AccountId>>;

		LockedEvents get(fn locked_events): 
        map hasher(twox_64_concat) u32 => Option<LockedEvent<<T as frame_system::Config>::AccountId>>;

        LockedEventsLength get(fn locked_events_length): u32 = 0;
	}
	add_extra_genesis {
		config(validators): Vec<(<T as frame_system::Config>::AccountId, u64)>;
		build(|config| Module::<T>::initialize_validator_set(&config.validators))
	}
}

decl_event!(
	/// Events generated by the module.
	pub enum Event<T>
	where
		AccountId = <T as frame_system::Config>::AccountId,
	{
		/// Event generated when a new voter votes on a validator set.
		/// \[validator_set, voter\]
		NewVoterFor(ValidatorSet<AccountId>, AccountId),
	}
);

decl_error! {
	/// Error for the octopus appchain module.
	pub enum Error for Module<T: Config> {
		/// No CurrentValidatorSet.
		NoCurrentValidatorSet,
		/// The sequence number of new validator set was wrong.
		WrongSequenceNumber,
		/// Must be a validator.
		NotValidator,
	}
}

decl_module! {
	/// A public part of the pallet.
	pub struct Module<T: Config> for enum Call where origin: T::Origin {
		fn deposit_event() = default;

		#[weight = 0]
		pub fn mint_token(
			origin,
			receriver_id: T::AccountId,
			token_id: Vec<u8>,
			amount: u64
		) -> DispatchResult {
			let receiver = <T::Lookup as StaticLookup>::unlookup(receriver_id.clone());
			let asset_id = <T as pallet_assets::Config>::AssetIdOf::convert(0).unwrap();
			let amount = <T as pallet_assets::Config>::BalanceOf::convert(amount).unwrap();
			
			let token_id = sp_std::str::from_utf8(&token_id).unwrap_or("UNKNOWN");

			let result = <pallet_assets::Pallet<T>>::mint(origin, asset_id, receiver.clone(), amount.into());
			log::info!(
				"️️️🐙 mint {:#?} to {:#?}, result: {:#?}",
				token_id,
				receiver,
				result
			);
			Ok(())
		}

		/// Submit a new set of validators and vote on this set.
		///
		/// If the set already exists in the CandidateValidatorSets, then the only thing
		/// to do is vote for this set.
		#[weight = 0]
		pub fn submit_validator_set(
			origin,
			payload: ValidatorSetPayload<T::Public, T::BlockNumber, <T as frame_system::Config>::AccountId>,
			_signature: T::Signature,
		) -> DispatchResult {
			// This ensures that the function can only be called via unsigned transaction.
			ensure_none(origin)?;
			let cur_val_set = <CurrentValidatorSet<T>>::get().ok_or(Error::<T>::NoCurrentValidatorSet)?;
			let who = payload.public.clone().into_account();
			//
			log::info!(
				"️️️🐙 current_validator_set: {:#?},\nnext_validator_set: {:#?},\nwho: {:?}",
				cur_val_set, payload.val_set, who
			);
			let candidates = <CandidateValidatorSets<T>>::get();
			for i in 0..candidates.len() {
				log::info!(
					"🐙 Candidate_index: {:#?},\ncandidate: {:#?},\nvoters: {:#?}",
					i, candidates.get(i), <Voters<T>>::get(i as u32)
				);
			}
			//
			ensure!(payload.val_set.sequence_number == cur_val_set.sequence_number + 1, Error::<T>::WrongSequenceNumber);

			let val = cur_val_set.validators
				.iter()
				.find(|v| {
					let id = <pallet_session::Module<T>>::key_owner(KEY_TYPE, &payload.public.clone().into_account().encode());
					log::info!("🐙 check {:#?} == {:#?}", v.id, id);
					<T as pallet_session::Config>::ValidatorIdOf::convert(v.id.clone()) == id
				});
			if val.is_none() {
				log::info!("🐙 Not a validator in current validator set: {:?}", payload.public.clone().into_account());
				return Err(Error::<T>::NotValidator.into());
			}
			let val = val.expect("Validator is valid; qed").clone();
			Self::add_validator_set(who, val, payload.val_set);
			//
			log::info!("🐙 after submit_validator_set");
			let candidates = <CandidateValidatorSets<T>>::get();
			for i in 0..candidates.len() {
				log::info!(
					"🐙 candidate_index: {:#?},\ncandidate: {:#?},\nvoters: {:#?}",
					i, candidates.get(i), <Voters<T>>::get(i as u32)
				);
			}
			//

			Ok(())
		}

		#[weight = 0]
		pub fn submit_locked_events(
			origin,
			payload: LockedEventsPayload<T::Public, T::BlockNumber, <T as frame_system::Config>::AccountId>,
			_signature: T::Signature,
		) -> DispatchResult {
            ensure_none(origin)?;
            let events: Vec<LockedEvent<<T as frame_system::Config>::AccountId>> = payload.events.clone();

            let mut start_idx = Self::locked_events_length();
            for event in events.iter() {
                <LockedEvents<T>>::insert(start_idx, event);
                start_idx += 1;
            }

            LockedEventsLength::put(start_idx);
            log::info!("🐙 Locked Events Updated! Events length: {:?}", start_idx);
            Ok(())
        }

		/// Offchain Worker entry point.
		///
		/// By implementing `fn offchain_worker` within `decl_module!` you declare a new offchain
		/// worker.
		/// This function will be called when the node is fully synced and a new best block is
		/// succesfuly imported.
		/// Note that it's not guaranteed for offchain workers to run on EVERY block, there might
		/// be cases where some blocks are skipped, or for some the worker runs twice (re-orgs),
		/// so the code should be able to handle that.
		/// You can use `Local Storage` API to coordinate runs of the worker.
		fn offchain_worker(block_number: T::BlockNumber) {

			if !Self::should_send(block_number) {
				return;
			}

			if let Err(e) = Self::fetch_and_update_locked_events(block_number) {
                log::info!("🐙 Update lock events error: {}", e);
            }

			// let appchain_id = T::AppchainId::get();
			// if appchain_id == 0 {
			// 	// detach appchain from motherchain when appchain_id == 0
			// 	return;
			// }
			let parent_hash = <system::Pallet<T>>::block_hash(block_number - 1u32.into());
			log::info!("🐙 Current block: {:?} (parent hash: {:?})", block_number, parent_hash);

			let next_seq_num;
			if let Some(cur_val_set) = <CurrentValidatorSet<T>>::get() {
				next_seq_num = cur_val_set.sequence_number + 1;
			} else {
				log::info!("🐙 CurrentValidatorSet must be initialized.");
				return;
			}
			log::info!("🐙 Next validator set sequenc number: {}", next_seq_num);

			if let Err(e) = Self::fetch_and_update_validator_set(block_number, next_seq_num) {
				log::info!("🐙 Error: {}", e);
			}
		}
	}
}

/// Most of the functions are moved outside of the `decl_module!` macro.
///
/// This greatly helps with error messages, as the ones inside the macro
/// can sometimes be hard to debug.
impl<T: Config> Module<T> {
	fn initialize_validator_set(
		vals: &Vec<(
			<T as frame_system::Config>::AccountId,
			u64,
		)>,
	) {
		if vals.len() != 0 {
			assert!(
				<CurrentValidatorSet<T>>::get().is_none(),
				"CurrentValidatorSet is already initialized!"
			);
			<CurrentValidatorSet<T>>::put(ValidatorSet {
				sequence_number: 0,
				validators: vals
					.iter()
					.map(|x| Validator {
						id: x.0.clone(),
						weight: x.1,
					})
					.collect::<Vec<_>>(),
			});
		}
	}

	fn should_send(block_number: T::BlockNumber) -> bool {
		/// A friendlier name for the error that is going to be returned in case we are in the grace
		/// period.
		const RECENTLY_SENT: () = ();

		// Start off by creating a reference to Local Storage value.
		// Since the local storage is common for all offchain workers, it's a good practice
		// to prepend your entry with the module name.
		let val = StorageValueRef::persistent(b"octopus_appchain::last_send");
		// The Local Storage is persisted and shared between runs of the offchain workers,
		// and offchain workers may run concurrently. We can use the `mutate` function, to
		// write a storage entry in an atomic fashion. Under the hood it uses `compare_and_set`
		// low-level method of local storage API, which means that only one worker
		// will be able to "acquire a lock" and send a transaction if multiple workers
		// happen to be executed concurrently.
		let res = val.mutate(|last_send: Option<Option<T::BlockNumber>>| {
			// We match on the value decoded from the storage. The first `Option`
			// indicates if the value was present in the storage at all,
			// the second (inner) `Option` indicates if the value was succesfuly
			// decoded to expected type (`T::BlockNumber` in our case).
			match last_send {
				// If we already have a value in storage and the block number is recent enough
				// we avoid sending another transaction at this time.
				Some(Some(block)) if block_number < block + T::GracePeriod::get() => {
					Err(RECENTLY_SENT)
				}
				// In every other case we attempt to acquire the lock and send a transaction.
				_ => Ok(block_number),
			}
		});

		// The result of `mutate` call will give us a nested `Result` type.
		// The first one matches the return of the closure passed to `mutate`, i.e.
		// if we return `Err` from the closure, we get an `Err` here.
		// In case we return `Ok`, here we will have another (inner) `Result` that indicates
		// if the value has been set to the storage correctly - i.e. if it wasn't
		// written to in the meantime.
		match res {
			// The value has been set correctly, which means we can safely send a transaction now.
			Ok(Ok(_block_number)) => true,
			// We are in the grace period, we should not send a transaction this time.
			Err(RECENTLY_SENT) => false,
			// We wanted to send a transaction, but failed to write the block number (acquire a
			// lock). This indicates that another offchain worker that was running concurrently
			// most likely executed the same logic and succeeded at writing to storage.
			// Thus we don't really want to send the transaction, knowing that the other run
			// already did.
			Ok(Err(_)) => false,
		}
	}

	fn fetch_and_update_locked_events(
        block_number: T::BlockNumber,
    ) -> Result<(), &'static str> {

        log::info!("🐙 in fetch_and_update_locked_events");

        let start_index = Self::locked_events_length();
        let events = Self::fetch_locked_events(
            T::LOCKER_CONTRACT_NAME.to_vec(),
            T::AppchainId::get(),
            start_index,
            10
        )
        .map_err(|_| "Failed to fetch locked events")?;

        if events.len() <= 0 {
            return Ok(());
        }

        log::info!(
            "🐙 got locked events: {:#?}, appchain id: {:#?}, start index: {:#?}, events len: {:#?}", 
            events, 
            T::AppchainId::get(), 
            start_index,
            events.len()
        );

        // -- Sign using any account
        let (_, result) = Signer::<T, T::AppCrypto>::any_account()
            .send_unsigned_transaction(
                |account| LockedEventsPayload {
                    public: account.public.clone(),
                    block_number,
                    events: events.clone(),
                },
                |payload, signature| Call::submit_locked_events(payload, signature),
            )
            .ok_or("🐙 No local accounts accounts available.")?;
        result.map_err(|()| "🐙 Unable to submit transaction")?;

		// mint assets
		
		let signer = Signer::<T, T::AppCrypto>::all_accounts();
		if !signer.can_sign() {
			return Err(
				"No local accounts available. Consider adding one via `author_insertKey` RPC."
			)?
		}
		
		for event in events.iter() {
			
			let _result =  Signer::<T, T::AppCrypto>::all_accounts()
				.send_signed_transaction(
					|_account| {
						Call::mint_token(event.receiver_id.clone(), event.token_id.clone(), event.amount)
					}
				);
        	// result.map_err(|()| "🐙 Unable to submit transaction")?;
		}
        
        Ok(())
       
    }

    fn fetch_locked_events(
        locker_contract: Vec<u8>,
        appchain_id: u32,
        start: u32,
        limit: u32,
    ) -> Result<Vec<LockedEvent<<T as frame_system::Config>::AccountId>>, http::Error> {
        let deadline = sp_io::offchain::timestamp().add(Duration::from_millis(2_000));
		
		let args = Self::encode_locked_args(appchain_id, start, limit).ok_or_else(|| {
			log::info!("🐙 Encode args error");
			http::Error::Unknown
		})?;

        let mut body = br#"
		{
			"jsonrpc": "2.0",
			"id": "dontcare",
			"method": "query",
			"params": {
				"request_type": "call_function",
				"finality": "final",
				"account_id": ""#
			.to_vec();
        body.extend(&locker_contract);
        body.extend(
			br#"",
				"method_name": "get_locked_events",
				"args_base64": ""#,
		);
		body.extend(&args);
		body.extend(
			br#""
			}
		}"#,
		);

        let request = http::Request::default()
			.method(http::Method::Post)
			.url("https://rpc.testnet.near.org")
			.body(vec![body])
			.add_header("Content-Type", "application/json");

        let pending = request
			.deadline(deadline)
			.send()
			.map_err(|_| http::Error::IoError)?;

        let response = pending
			.try_wait(deadline)
			.map_err(|_| http::Error::DeadlineReached)??;

        if response.code != 200 {
            log::info!("🐙 Unexpected status code: {}", response.code);
            return Err(http::Error::Unknown);
        }

        let body = response.body().collect::<Vec<u8>>();

		// Create a str slice from the body.
		let body_str = sp_std::str::from_utf8(&body).map_err(|_| {
			log::info!("🐙 No UTF8 body");
			http::Error::Unknown
		})?;
		log::info!("🐙 Got response: {:?}", body_str);

        let events = match Self::parse_events(body_str) {
			Some(e) => Ok(e),
			None => {
				log::info!(
					"🐙 Unable to extract events from the response: {:?}",
					body_str
				);
				Err(http::Error::Unknown)
			}
		}?;

        log::info!("🐙 Got events: {:?}", events);

        Ok(events)
    }

	fn fetch_and_update_validator_set(
		block_number: T::BlockNumber,
		next_seq_num: u32,
	) -> Result<(), &'static str> {
		log::info!("🐙 in fetch_and_update_validator_set");

		// Make an external HTTP request to fetch the current validator set.
		// Note this call will block until response is received.
		let next_val_set = Self::fetch_validator_set(
			T::RELAY_CONTRACT_NAME.to_vec(),
			T::AppchainId::get(),
			next_seq_num,
		)
		.map_err(|_| "Failed to fetch validator set")?;
		log::info!("🐙 new validator set: {:#?}", next_val_set);

		// -- Sign using any account
		let (_, result) = Signer::<T, T::AppCrypto>::any_account()
			.send_unsigned_transaction(
				|account| ValidatorSetPayload {
					public: account.public.clone(),
					block_number,
					val_set: next_val_set.clone(),
				},
				|payload, signature| Call::submit_validator_set(payload, signature),
			)
			.ok_or("🐙 No local accounts accounts available.")?;
		result.map_err(|()| "🐙 Unable to submit transaction")?;

		Ok(())
	}

	/// Fetch the validator set of a specified appchain with seq_num from relay contract.
	fn fetch_validator_set(
		relay_contract: Vec<u8>,
		appchain_id: u32,
		seq_num: u32,
	) -> Result<ValidatorSet<<T as frame_system::Config>::AccountId>, http::Error> {
		// We want to keep the offchain worker execution time reasonable, so we set a hard-coded
		// deadline to 2s to complete the external call.
		// You can also wait idefinitely for the response, however you may still get a timeout
		// coming from the host machine.
		let deadline = sp_io::offchain::timestamp().add(Duration::from_millis(2_000));
		// Initiate an external HTTP GET request.
		// This is using high-level wrappers from `sp_runtime`, for the low-level calls that
		// you can find in `sp_io`. The API is trying to be similar to `reqwest`, but
		// since we are running in a custom WASM execution environment we can't simply
		// import the library here.
		let args = Self::encode_args(appchain_id, seq_num).ok_or_else(|| {
			log::info!("🐙 Encode args error");
			http::Error::Unknown
		})?;

		let mut body = br#"
		{
			"jsonrpc": "2.0",
			"id": "dontcare",
			"method": "query",
			"params": {
				"request_type": "call_function",
				"finality": "final",
				"account_id": ""#
			.to_vec();
		body.extend(&relay_contract);
		body.extend(
			br#"",
				"method_name": "get_validator_set",
				"args_base64": ""#,
		);
		body.extend(&args);
		body.extend(
			br#""
			}
		}"#,
		);
		let request = http::Request::default()
			.method(http::Method::Post)
			.url("https://rpc.testnet.near.org")
			.body(vec![body])
			.add_header("Content-Type", "application/json");
		// We set the deadline for sending of the request, note that awaiting response can
		// have a separate deadline. Next we send the request, before that it's also possible
		// to alter request headers or stream body content in case of non-GET requests.
		let pending = request
			.deadline(deadline)
			.send()
			.map_err(|_| http::Error::IoError)?;

		// The request is already being processed by the host, we are free to do anything
		// else in the worker (we can send multiple concurrent requests too).
		// At some point however we probably want to check the response though,
		// so we can block current thread and wait for it to finish.
		// Note that since the request is being driven by the host, we don't have to wait
		// for the request to have it complete, we will just not read the response.
		let response = pending
			.try_wait(deadline)
			.map_err(|_| http::Error::DeadlineReached)??;
		// Let's check the status code before we proceed to reading the response.
		if response.code != 200 {
			log::info!("🐙 Unexpected status code: {}", response.code);
			return Err(http::Error::Unknown);
		}

		// Next we want to fully read the response body and collect it to a vector of bytes.
		// Note that the return object allows you to read the body in chunks as well
		// with a way to control the deadline.
		let body = response.body().collect::<Vec<u8>>();

		// Create a str slice from the body.
		let body_str = sp_std::str::from_utf8(&body).map_err(|_| {
			log::info!("🐙 No UTF8 body");
			http::Error::Unknown
		})?;
		log::info!("🐙 Got response: {:?}", body_str);

		let val_set = match Self::parse_validator_set(body_str) {
			Some(val_set) => Ok(val_set),
			None => {
				log::info!(
					"🐙 Unable to extract validator set from the response: {:?}",
					body_str
				);
				Err(http::Error::Unknown)
			}
		}?;

		log::info!("🐙 Got validator set: {:?}", val_set);

		Ok(val_set)
	}

	fn encode_args(appchain_id: u32, seq_num: u32) -> Option<Vec<u8>> {
		let a = String::from("{\"appchain_id\":");
		let appchain_id = appchain_id.to_string();
		let b = String::from(",\"seq_num\":");
		let seq_num = seq_num.to_string();
		let c = String::from("}");
		let json = a + &appchain_id + &b + &seq_num + &c;
		let res = base64::encode(json).into_bytes();
		Some(res)
	}

	fn encode_locked_args(appchain_id: u32, start: u32, limit: u32) -> Option<Vec<u8>> {
		let a = String::from("{\"appchain_id\":");
		let appchain_id = appchain_id.to_string();
		let b = String::from(",\"start\":");
		let start = start.to_string();
        let c = String::from(",\"limit\":");
        let limit = limit.to_string();
		let d = String::from("}");
		let json = a + &appchain_id + &b + &start + &c + &limit + &d;
		let res = base64::encode(json).into_bytes();
		Some(res)
	}

	fn parse_events(
        body_str: &str,
    ) -> Option<Vec<LockedEvent<<T as frame_system::Config>::AccountId>>> {
        let result = Self::extract_result(body_str).ok_or_else(|| {
			log::info!("🐙 Can't extract result from body");
			Option::<ValidatorSet<<T as frame_system::Config>::AccountId>>::None
		}).ok()?;

		let result_str = sp_std::str::from_utf8(&result).map_err(|_| {
			log::info!("🐙 No UTF8 result");
			Option::<ValidatorSet<<T as frame_system::Config>::AccountId>>::None
		}).ok()?;

		log::info!("🐙 Got result: {:?}", result_str);

        let val = lite_json::parse_json(result_str);
        let mut events: Vec<LockedEvent<<T as frame_system::Config>::AccountId>> = vec![];
        val.ok().and_then(|v| match v {
            JsonValue::Array(arr) => {
                arr.iter().for_each(|v| match v {
                    JsonValue::Object(obj) => {
                        let seq_num = obj
                            .clone()
                            .into_iter()
                            .find(|(k, _)| {
                                let mut seq_num = "seq_num".chars();
                                k.iter().all(|k| Some(*k) == seq_num.next())
                            })
                            .and_then(|v| match v.1 {
                                JsonValue::Number(number) => Some(number),
                                _ => None,
                            });
                        let token_id = obj
                            .clone()
                            .into_iter()
                            .find(|(k, _)| {
                                let mut seq_num = "token_id".chars();
                                k.iter().all(|k| Some(*k) == seq_num.next())
                            })
                            .and_then(|v| match v.1 {
                                JsonValue::String(s) => {
                                    let data: Vec<u8> = s
                                        .iter()
                                        .map(|c| *c as u8)
                                        .collect::<Vec<_>>();
                                    Some(data)
                                },
                                _ => None,
                            });
                        let _appchain_id = obj
                            .clone()
                            .into_iter()
                            .find(|(k, _)| {
                                let mut appchain_id = "appchain_id".chars();
                                k.iter().all(|k| Some(*k) == appchain_id.next())
                            })
                            .and_then(|v| match v.1 {
                                JsonValue::Number(number) => Some(number),
                                _ => None,
                            });
                        let receiver_id = obj
                            .clone()
                            .into_iter()
                            .find(|(k, _)| {
                                let mut id = "receiver_id".chars();
                                k.iter().all(|k| Some(*k) == id.next())
                            })
                            .and_then(|v| match v.1 {
                                JsonValue::String(s) => {
                                    let data: Vec<u8> = s
                                        .iter()
										.skip(2)
                                        .map(|c| *c as u8)
                                        .collect::<Vec<_>>();
                                    let b = hex::decode(data).map_err(|_| {
                                        log::info!("🐙 Not a valid hex string");
                                        Option::<ValidatorSet<<T as frame_system::Config>::AccountId>>::None
                                    }).ok()?;
                                    <T as frame_system::Config>::AccountId::decode(
                                        &mut &b[..],
                                    )
                                    .ok()
                                }
                                _ => None,
                            });
                        let amount = obj
                            .clone()
                            .into_iter()
                            .find(|(k, _)| {
                                let mut amount = "amount".chars();
                                k.iter().all(|k| Some(*k) == amount.next())
                            })
                            .and_then(|v| match v.1 {
                                JsonValue::String(s) => {
                                    let num_str: String = s.iter().collect();
                                    let num: u64 = num_str.parse::<u64>().unwrap_or(0);
                                    Some(num)
                                },
                                _ => None,
                            });
                        if seq_num.is_some() {
                            let zero_number = NumberValue {
                                integer: 0,
                                fraction: 0,
                                fraction_length: 0,
                                exponent: 0
                            };

                            let zero_address_hex = hex::decode("0000000000000000000000000000000000000000000000000000000000000000").ok().unwrap();
                            let zero_address = <T as frame_system::Config>::AccountId::decode(&mut &zero_address_hex[..]).unwrap();

                            let seq_num = seq_num.unwrap_or(zero_number.clone()).integer as u32;
                            let token_id = token_id.unwrap_or("INVALID".as_bytes().to_vec());
                            // let appchain_id = appchain_id.expect("seq_num is invalid; qed").integer as u32;
                            let amount = amount.unwrap_or(0);

                            let receiver_id = receiver_id.unwrap_or(zero_address);
                            events.push(LockedEvent {
                                sequence_number: seq_num,
                                token_id: token_id,
                                receiver_id: receiver_id,
                                amount: amount
                            });
                        }
                    }
                    _ => (),
                });
                Some(0)
            }
            _ => None
        });
        Some(events)
    }

	fn parse_validator_set(
		body_str: &str,
	) -> Option<ValidatorSet<<T as frame_system::Config>::AccountId>> {
		// TODO
		let result = Self::extract_result(body_str).ok_or_else(|| {
			log::info!("🐙 Can't extract result from body");
			Option::<ValidatorSet<<T as frame_system::Config>::AccountId>>::None
		}).ok()?;

		let result_str = sp_std::str::from_utf8(&result).map_err(|_| {
			log::info!("🐙 No UTF8 result");
			Option::<ValidatorSet<<T as frame_system::Config>::AccountId>>::None
		}).ok()?;

		log::info!("🐙 Got result: {:?}", result_str);
		let mut val_set: ValidatorSet<<T as frame_system::Config>::AccountId> = ValidatorSet {
			sequence_number: 0,
			validators: vec![],
		};
		let val = lite_json::parse_json(result_str);
		val.ok().and_then(|v| match v {
			JsonValue::Object(obj) => {
				val_set.sequence_number = obj
					.clone()
					.into_iter()
					.find(|(k, _)| {
						let mut sequence_number = "seq_num".chars();
						k.iter().all(|k| Some(*k) == sequence_number.next())
					})
					.and_then(|v| match v.1 {
						JsonValue::Number(number) => Some(number),
						_ => None,
					})?
					.integer as u32;
				obj.into_iter()
					.find(|(k, _)| {
						let mut validators = "validators".chars();
						k.iter().all(|k| Some(*k) == validators.next())
					})
					.and_then(|(_, v)| match v {
						JsonValue::Array(vs) => {
							vs.iter().for_each(|v| match v {
								JsonValue::Object(obj) => {
									let id = obj
										.clone()
										.into_iter()
										.find(|(k, _)| {
											let mut id = "id".chars();
											k.iter().all(|k| Some(*k) == id.next())
										})
										.and_then(|v| match v.1 {
											JsonValue::String(s) => {
												let data: Vec<u8> = s
													.iter()
													.skip(2)
													.map(|c| *c as u8)
													.collect::<Vec<_>>();
												let b = hex::decode(data).map_err(|_| {
													log::info!("🐙 Not a valid hex string");
													Option::<ValidatorSet<<T as frame_system::Config>::AccountId>>::None
												}).ok()?;
												<T as frame_system::Config>::AccountId::decode(
													&mut &b[..],
												)
												.ok()
											}
											_ => None,
										});
									let weight = obj
										.clone()
										.into_iter()
										.find(|(k, _)| {
											let mut weight = "weight".chars();
											k.iter().all(|k| Some(*k) == weight.next())
										})
										.and_then(|v| match v.1 {
											JsonValue::Number(number) => Some(number),
											_ => None,
										});
									if id.is_some() && weight.is_some() {
										let id = id.expect("id is valid; qed");
										let weight = weight.expect("weight is valid; qed").integer as u64;
										val_set.validators.push(Validator {
											id: id,
											weight: weight,
										});
									}
								}
								_ => (),
							});
							Some(0)
						}
						_ => None,
					});
				Some(val_set)
			}
			_ => None,
		})
	}

	fn extract_result(body_str: &str) -> Option<Vec<u8>> {
		let val = lite_json::parse_json(body_str);
		val.ok().and_then(|v| match v {
			JsonValue::Object(obj) => {
				let version = obj
					.clone()
					.into_iter()
					.find(|(k, _)| {
						let mut jsonrpc = "jsonrpc".chars();
						k.iter().all(|k| Some(*k) == jsonrpc.next())
					})
					.and_then(|v| match v.1 {
						JsonValue::String(s) => Some(s),
						_ => None,
					})?;
				log::info!("🐙 version: {:?}", version);
				let id = obj
					.clone()
					.into_iter()
					.find(|(k, _)| {
						let mut id = "id".chars();
						k.iter().all(|k| Some(*k) == id.next())
					})
					.and_then(|v| match v.1 {
						JsonValue::String(s) => Some(s),
						_ => None,
					})?;
				log::info!("🐙 id: {:?}", id);
				obj.into_iter()
					.find(|(k, _)| {
						let mut result = "result".chars();
						k.iter().all(|k| Some(*k) == result.next())
					})
					.and_then(|(_, v)| match v {
						JsonValue::Object(obj) => {
							obj.into_iter()
								.find(|(k, _)| {
									let mut values = "result".chars();
									k.iter().all(|k| Some(*k) == values.next())
								})
								.and_then(|(_, v)| match v {
									JsonValue::Array(vs) => {
										// TODO
										let res: Vec<u8> = vs
											.iter()
											.map(|jv| match jv {
												JsonValue::Number(n) => n.integer as u8,
												_ => 0,
											})
											.collect();
										Some(res)
									}
									_ => None,
								})
						}
						_ => None,
					})
			}
			_ => None,
		})
	}

	/// Add new validator set to the CandidateValidatorSets.
	fn add_validator_set(
		who: T::AccountId,
		val: Validator<<T as frame_system::Config>::AccountId>,
		new_val_set: ValidatorSet<<T as frame_system::Config>::AccountId>,
	) {
		log::info!("🐙 Adding to the voters: {:#?}", new_val_set);
		let index = 0;
		<CandidateValidatorSets<T>>::mutate(|val_sets| {
			// TODO
			if val_sets.len() == 0 {
				val_sets.push(new_val_set.clone());
			}
		});

		<Voters<T>>::mutate(index, |vals| {
			let exist = vals.iter().find(|v| v.id == val.id);
			match exist {
				Some(id) => {
					log::info!("🐙 duplicated ocw tx: {:?}", id);
				}
				None => vals.push(val),
			}
		});

		Self::deposit_event(RawEvent::NewVoterFor(new_val_set, who));
	}

	fn validate_transaction_parameters(
		block_number: &T::BlockNumber,
		val_set: &ValidatorSet<<T as frame_system::Config>::AccountId>,
		account_id: <T as frame_system::Config>::AccountId,
	) -> TransactionValidity {
		// Let's make sure to reject transactions from the future.
		let current_block = <system::Pallet<T>>::block_number();
		if &current_block < block_number {
			log::info!(
				"🐙 InvalidTransaction => current_block: {:?}, block_number: {:?}",
				current_block,
				block_number
			);
			return InvalidTransaction::Future.into();
		}

		ValidTransaction::with_tag_prefix("OctopusAppchain")
			// We set base priority to 2**20 and hope it's included before any other
			// transactions in the pool. Next we tweak the priority depending on the
			// sequence number of the validator set.
			.priority(T::UnsignedPriority::get().saturating_add(val_set.sequence_number as _))
			// This transaction does not require anything else to go before into the pool.
			//.and_requires()
			// One can only vote on the validator set with the same seq_num once.
			.and_provides((val_set.sequence_number, account_id))
			// The transaction is only valid for next 5 blocks. After that it's
			// going to be revalidated by the pool.
			.longevity(5)
			// It's fine to propagate that transaction to other peers, which means it can be
			// created even by nodes that don't produce blocks.
			// Note that sometimes it's better to keep it for yourself (if you are the block
			// producer), since for instance in some schemes others may copy your solution and
			// claim a reward.
			.propagate(true)
			.build()
	}

	fn validate_locked_events_transaction_parameters(
        block_number: &T::BlockNumber,
		_events: &Vec<LockedEvent<<T as frame_system::Config>::AccountId>>,
		account_id: <T as frame_system::Config>::AccountId,
    ) -> TransactionValidity {
        // Let's make sure to reject transactions from the future.
		let current_block = <system::Pallet<T>>::block_number();
		if &current_block < block_number {
			log::info!(
				"🐙 InvalidTransaction => current_block: {:?}, block_number: {:?}",
				current_block,
				block_number
			);
			return InvalidTransaction::Future.into();
		}

        ValidTransaction::with_tag_prefix("OctopusAppchain")
			.priority(T::UnsignedPriority::get().saturating_add(Self::locked_events_length() as _))
			.and_provides((Self::locked_events_length(), account_id))
			.longevity(5)
			.propagate(true)
			.build()

    }
}

#[allow(deprecated)] // ValidateUnsigned
impl<T: Config> frame_support::unsigned::ValidateUnsigned for Module<T> {
	type Call = Call<T>;

	/// Validate unsigned call to this module.
	///
	/// By default unsigned transactions are disallowed, but implementing the validator
	/// here we make sure that some particular calls (the ones produced by offchain worker)
	/// are being whitelisted and marked as valid.
	fn validate_unsigned(_source: TransactionSource, call: &Self::Call) -> TransactionValidity {
		// Firstly let's check that we call the right function.
		if let Call::submit_validator_set(ref payload, ref signature) = call {
			let signature_valid =
				SignedPayload::<T>::verify::<T::AppCrypto>(payload, signature.clone());
			if !signature_valid {
				return InvalidTransaction::BadProof.into();
			}
			Self::validate_transaction_parameters(
				&payload.block_number,
				&payload.val_set,
				payload.public.clone().into_account(),
			)
		} else if let Call::submit_locked_events(ref payload, ref signature) = call  {
            let signature_valid =
				SignedPayload::<T>::verify::<T::AppCrypto>(payload, signature.clone());
			if !signature_valid {
				return InvalidTransaction::BadProof.into();
			}
            Self::validate_locked_events_transaction_parameters(
				&payload.block_number,
				&payload.events,
				payload.public.clone().into_account(),
			)
        } else {
			InvalidTransaction::Call.into()
		}
	}
}

pub type SessionIndex = u32;

impl<T: Config> pallet_session::SessionManager<T::AccountId> for Module<T> {
	fn new_session(new_index: SessionIndex) -> Option<Vec<T::AccountId>> {
		log::info!(
			"🐙 [{:?}] planning new_session({})",
			<frame_system::Pallet<T>>::block_number(),
			new_index
		);
		if let Some(cur_val_set) = <CurrentValidatorSet<T>>::get() {
			//
			log::info!(
				"🐙 current_validator_set: {:#?}",
				cur_val_set
			);
			let candidates = <CandidateValidatorSets<T>>::get();
			for i in 0..candidates.len() {
				log::info!(
					"🐙 candidate_index: {:?},\ncandidate: {:#?},\nvoters: {:#?}",
					i,
					candidates.get(i),
					<Voters<T>>::get(i as u32)
				);
			}
			//
			let total_weight: u64 = cur_val_set.validators.iter().map(|v| v.weight).sum();
			// TODO
			let next_val_set = <Voters<T>>::iter()
				.find(|(_k, v)| v.iter().map(|x| x.weight).sum::<u64>() == total_weight)
				.map(|(index, _v)| {
					log::info!("🐙 total_weight: {}, index: {}", total_weight, index);
					<CandidateValidatorSets<T>>::get()[index as usize].clone()
				});
			match next_val_set {
				Some(new_val_set) => {
					// TODO: transaction
					<CurrentValidatorSet<T>>::put(new_val_set.clone());
					let candidates = <CandidateValidatorSets<T>>::get();
					for i in 0..candidates.len() {
						<Voters<T>>::remove(i as u32);
					}
					<CandidateValidatorSets<T>>::kill();
					log::info!("🐙 validator set changed to: {:#?}", new_val_set.clone());
					Some(
						new_val_set
							.validators
							.into_iter()
							.map(|vals| vals.id)
							.collect(),
					)
				}
				None => {
					log::info!("🐙 validator set has't changed");
					None
				}
			}
		} else {
			None
		}
	}

	fn start_session(start_index: SessionIndex) {
		log::info!(
			"🐙 [{:?}] starting start_session({})",
			<frame_system::Pallet<T>>::block_number(),
			start_index
		);
	}

	fn end_session(end_index: SessionIndex) {
		log::info!(
			"🐙 [{:?}] ending end_session({})",
			<frame_system::Pallet<T>>::block_number(),
			end_index
		);
	}
}

impl<T: Config> sp_runtime::BoundToRuntimeAppPublic for Module<T> {
	type Public = crypto::AuthorityId;
}

impl<T: Config> OneSessionHandler<T::AccountId> for Module<T> {
	type Key = crypto::AuthorityId;

	fn on_genesis_session<'a, I: 'a>(_authorities: I)
	where
		I: Iterator<Item = (&'a T::AccountId, Self::Key)>,
	{
		// ignore
	}

	fn on_new_session<'a, I: 'a>(_changed: bool, _validators: I, _queued_validators: I)
	where
		I: Iterator<Item = (&'a T::AccountId, Self::Key)>,
	{
		// ignore
	}

	fn on_disabled(_i: usize) {
		// ignore
	}
}