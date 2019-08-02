use crate::rstd::borrow::Borrow;
use crate::rstd::boxed::Box;
use crate::rstd::marker::PhantomData;
use codec::{Codec, Encode, Decode, EncodeAppend};
use runtime_io::{twox_64, twox_128, blake2_128, twox_256, blake2_256};
use super::unhashed;
use super::child;

/// Hash storage keys with `concat(twox64(key), key)`
pub struct Twox64Concat;
impl Hasher for Twox64Concat {
	fn using_hashed<R, F: FnOnce(&[u8]) -> R>(x: &[u8], f: F) -> R {
		let hashed = twox_64(x)
			.into_iter()
			.chain(x.into_iter())
			.cloned()
			.collect::<Vec<_>>();
		f(&hashed)
	}
}

/// Hash storage keys with blake2 128
pub struct Blake2_128;
impl Hasher for Blake2_128 {
	fn using_hashed<R, F: FnOnce(&[u8]) -> R>(x: &[u8], f: F) -> R {
		f(&blake2_128(x))
	}
}

/// Hash storage keys with blake2 256
pub struct Blake2_256;
impl Hasher for Blake2_256 {
	fn using_hashed<R, F: FnOnce(&[u8]) -> R>(x: &[u8], f: F) -> R {
		f(&blake2_256(x))
	}
}

/// Hash storage keys with twox 128
pub struct Twox128;
impl Hasher for Twox128 {
	fn using_hashed<R, F: FnOnce(&[u8]) -> R>(x: &[u8], f: F) -> R {
		f(&twox_128(x))
	}
}

/// Hash storage keys with twox 256
pub struct Twox256;
impl Hasher for Twox256 {
	fn using_hashed<R, F: FnOnce(&[u8]) -> R>(x: &[u8], f: F) -> R {
		f(&twox_256(x))
	}
}

pub struct NoHash;
impl Hasher for NoHash {
	fn using_hashed<R, F: FnOnce(&[u8]) -> R>(x: &[u8], f: F) -> R {
		f(x)
	}
}

pub trait Hasher {
	fn using_hashed<R, F: FnOnce(&[u8]) -> R>(x: &[u8], f: F) -> R;
}
pub trait ConstSliceU8 {
	const CONST: &'static [u8];
}
pub struct NullConstSliceU8;
impl ConstSliceU8 for NullConstSliceU8 {
	const CONST: &'static [u8] = &[];
}

pub type TopStorage<H1, H2> = TopStoragePrefixed<H1, H2, NullConstSliceU8>;
pub struct TopStoragePrefixed<H1: Hasher, H2: Hasher, Prefix: ConstSliceU8>(PhantomData<(H1, H2, Prefix)>);
pub type ChildStorage<H1, H2, Keyspace> = ChildStoragePrefixed<H1, H2, Keyspace, NullConstSliceU8>;
pub struct ChildStoragePrefixed<H1: Hasher, H2: Hasher, Keyspace: ConstSliceU8, Prefix: ConstSliceU8>(PhantomData<(H1, H2, Keyspace, Prefix)>);

fn using_prefixed<R, F: FnOnce(&[u8]) -> R>(x: &[u8], prefix: &[u8], f: F) -> R {
	if prefix.is_empty() {
		f(x)
	} else {
		let mut r = Vec::with_capacity(x.len() + prefix.len());
		r.extend(prefix);
		r.extend(x);
		f(&r)
	}
}

fn using_suffixed<R, F: FnOnce(&[u8]) -> R>(x: &[u8], suffix: &[u8], f: F) -> R {
	if suffix.is_empty() {
		f(x)
	} else {
		let mut r = Vec::with_capacity(x.len() + suffix.len());
		r.extend(x);
		r.extend(suffix);
		f(&r)
	}
}

impl<H1: Hasher, H2: Hasher, Prefix: ConstSliceU8> TopStoragePrefixed<H1, H2, Prefix> {
	fn exists(key1: &[u8], key2: &[u8]) -> bool {
		H1::using_hashed(key1, |hashed_key1| using_prefixed(hashed_key1, Prefix::CONST, |prefixed_hashed_key1| H2::using_hashed(key2, |hashed_key2| using_suffixed(prefixed_hashed_key1, hashed_key2, |final_key| unhashed::exists(final_key)))))
	}

	fn get<T: Decode>(key1: &[u8], key2: &[u8]) -> Option<T> {
		H1::using_hashed(key1, |hashed_key1| using_prefixed(hashed_key1, Prefix::CONST, |prefixed_hashed_key1| H2::using_hashed(key2, |hashed_key2| using_suffixed(prefixed_hashed_key1, hashed_key2, |final_key| unhashed::get(final_key)))))
	}

	fn put<T: Encode>(key1: &[u8], key2: &[u8], value: &T) {
		H1::using_hashed(key1, |hashed_key1| using_prefixed(hashed_key1, Prefix::CONST, |prefixed_hashed_key1| H2::using_hashed(key2, |hashed_key2| using_suffixed(prefixed_hashed_key1, hashed_key2, |final_key| unhashed::put(final_key, value)))))
	}

	fn kill(key1: &[u8], key2: &[u8]) {
		H1::using_hashed(key1, |hashed_key1| using_prefixed(hashed_key1, Prefix::CONST, |prefixed_hashed_key1| H2::using_hashed(key2, |hashed_key2| using_suffixed(prefixed_hashed_key1, hashed_key2, |final_key| unhashed::kill(final_key)))))
	}

	fn kill_key1(key1: &[u8]) {
		H1::using_hashed(key1, |hashed_key1| using_prefixed(hashed_key1, Prefix::CONST, |prefixed_hashed_key1|  unhashed::kill_prefix(prefixed_hashed_key1)))
	}

	fn get_raw(key1: &[u8], key2: &[u8]) -> Option<Vec<u8>> {
		H1::using_hashed(key1, |hashed_key1| using_prefixed(hashed_key1, Prefix::CONST, |prefixed_hashed_key1| H2::using_hashed(key2, |hashed_key2| using_suffixed(prefixed_hashed_key1, hashed_key2, |final_key| unhashed::get_raw(final_key)))))
	}

	fn put_raw(key1: &[u8], key2: &[u8], value: &[u8]) {
		H1::using_hashed(key1, |hashed_key1| using_prefixed(hashed_key1, Prefix::CONST, |prefixed_hashed_key1| H2::using_hashed(key2, |hashed_key2| using_suffixed(prefixed_hashed_key1, hashed_key2, |final_key| unhashed::put_raw(final_key, value)))))
	}
}

impl<H1: Hasher, H2: Hasher, Keyspace: ConstSliceU8, Prefix: ConstSliceU8> ChildStoragePrefixed<H1, H2, Keyspace, Prefix> {
	fn exists(key1: &[u8], key2: &[u8]) -> bool {
		H1::using_hashed(key1, |hashed_key1| using_prefixed(hashed_key1, Prefix::CONST, |prefixed_hashed_key1| H2::using_hashed(key2, |hashed_key2| using_suffixed(prefixed_hashed_key1, hashed_key2, |final_key| child::exists(Keyspace::CONST, final_key)))))
	}

	fn get<T: Decode>(key1: &[u8], key2: &[u8]) -> Option<T> {
		H1::using_hashed(key1, |hashed_key1| using_prefixed(hashed_key1, Prefix::CONST, |prefixed_hashed_key1| H2::using_hashed(key2, |hashed_key2| using_suffixed(prefixed_hashed_key1, hashed_key2, |final_key| child::get(Keyspace::CONST, final_key)))))
	}

	fn put<T: Encode>(key1: &[u8], key2: &[u8], value: &T) {
		H1::using_hashed(key1, |hashed_key1| using_prefixed(hashed_key1, Prefix::CONST, |prefixed_hashed_key1| H2::using_hashed(key2, |hashed_key2| using_suffixed(prefixed_hashed_key1, hashed_key2, |final_key| child::put(Keyspace::CONST, final_key, value)))))
	}

	fn kill(key1: &[u8], key2: &[u8]) {
		H1::using_hashed(key1, |hashed_key1| using_prefixed(hashed_key1, Prefix::CONST, |prefixed_hashed_key1| H2::using_hashed(key2, |hashed_key2| using_suffixed(prefixed_hashed_key1, hashed_key2, |final_key| child::kill(Keyspace::CONST, final_key)))))
	}

	fn kill_key1(key1: &[u8]) {
		H1::using_hashed(key1, |hashed_key1| using_prefixed(hashed_key1, Prefix::CONST, |prefixed_hashed_key1|  child::kill_prefix(Keyspace::CONST, prefixed_hashed_key1)))
	}

	fn get_raw(key1: &[u8], key2: &[u8]) -> Option<Vec<u8>> {
		H1::using_hashed(key1, |hashed_key1| using_prefixed(hashed_key1, Prefix::CONST, |prefixed_hashed_key1| H2::using_hashed(key2, |hashed_key2| using_suffixed(prefixed_hashed_key1, hashed_key2, |final_key| child::get_raw(Keyspace::CONST, final_key)))))
	}

	fn put_raw(key1: &[u8], key2: &[u8], value: &[u8]) {
		H1::using_hashed(key1, |hashed_key1| using_prefixed(hashed_key1, Prefix::CONST, |prefixed_hashed_key1| H2::using_hashed(key2, |hashed_key2| using_suffixed(prefixed_hashed_key1, hashed_key2, |final_key| child::put_raw(Keyspace::CONST, final_key, value)))))
	}
}

pub trait StorageDoubleKey {
	/// True if the key exists in storage.
	fn exists(key1: &[u8], key2: &[u8]) -> bool;

	/// Load the bytes of a key from storage. Can panic if the type is incorrect.
	fn get<T: Decode>(key1: &[u8], key2: &[u8]) -> Option<T>;

	/// Put a value in under a key.
	fn put<T: Encode>(key1: &[u8], key2: &[u8], val: &T);

	/// Remove the bytes of a key from storage.
	fn kill(key1: &[u8], key2: &[u8]);

	/// Remove all key2 associated with key1.
	fn kill_key1(key1: &[u8]);

	/// Get a Vec of bytes from storage.
	fn get_raw(key1: &[u8], key2: &[u8]) -> Option<Vec<u8>>;

	/// Put a raw byte slice into storage.
	fn put_raw(key1: &[u8], key2: &[u8], value: &[u8]);
}

pub trait Storage {
	/// True if the key exists in storage.
	fn exists(key: &[u8]) -> bool;

	/// Load the bytes of a key from storage. Can panic if the type is incorrect.
	fn get<T: Decode>(key: &[u8]) -> Option<T>;

	/// Put a value in under a key.
	fn put<T: Encode>(key: &[u8], val: &T);

	/// Remove the bytes of a key from storage.
	fn kill(key: &[u8]);

	/// Get a Vec of bytes from storage.
	fn get_raw(key: &[u8]) -> Option<Vec<u8>>;

	/// Put a raw byte slice into storage.
	fn put_raw(key: &[u8], value: &[u8]);
}

impl<S: StorageDoubleKey> Storage for S {
	fn exists(key: &[u8]) -> bool { S::exists(key, &[]) }
	fn get<T: Decode>(key: &[u8]) -> Option<T> { S::get(key, &[]) }
	fn put<T: Encode>(key: &[u8], value: &T) { S::put(key, &[], value) }
	fn kill(key: &[u8]) { S::kill(key, &[]) }
	fn get_raw(key: &[u8]) -> Option<Vec<u8>> { S::get_raw(key, &[]) }
	fn put_raw(key: &[u8], value: &[u8]) { S::put_raw(key, &[], value) }
}

pub trait StorageValue<T: Codec> {
	/// The type that get/take returns.
	type Query;

	type Storage: Storage;

	/// Get the storage key.
	fn key() -> &'static [u8];

	fn from_optional_value_to_query(v: Option<T>) -> Self::Query;

	fn from_query_to_optional_value(v: Self::Query) -> Option<T>;
}

impl<T: Codec, G: StorageValue<T>> super::StorageValue<T> for G {
	type Query = G::Query;

	fn key() -> &'static [u8] {
		G::key()
	}

	fn exists() -> bool {
		G::Storage::exists(G::key())
	}

	fn get() -> Self::Query {
		G::from_optional_value_to_query(G::Storage::get(G::key()))
	}

	fn put<Arg: Borrow<T>>(val: Arg) {
		G::Storage::put(G::key(), val.borrow())
	}

	fn put_ref<Arg: ?Sized + Encode>(val: &Arg) where T: AsRef<Arg> {
		val.using_encoded(|b| G::Storage::put_raw(G::key(), b))
	}

	fn kill() {
		G::Storage::kill(G::key())
	}

	fn mutate<R, F: FnOnce(&mut G::Query) -> R>(f: F) -> R {
		// TODO TODO: avoid computing key everytime
		let mut val = G::get();

		let ret = f(&mut val);
		match G::from_query_to_optional_value(val) {
			Some(ref val) => G::put(val),
			None => G::kill(),
		}
		ret
	}

	fn take() -> G::Query {
		let key = G::key();
		let value = G::Storage::get(key);
		if value.is_some() {
			G::Storage::kill(key)
		}
		G::from_optional_value_to_query(value)
	}

	fn append<I: Encode>(items: &[I]) -> Result<(), &'static str>
		where T: EncodeAppend<Item=I>
	{
		let key = G::key();
		let encoded_value = G::Storage::get_raw(key)
			.unwrap_or_else(|| {
				match G::from_query_to_optional_value(G::from_optional_value_to_query(None)) {
					Some(value) => value.encode(),
					None => vec![],
				}
			});

		let new_val = <T as EncodeAppend>::append(
			encoded_value,
			items,
		).ok_or_else(|| "Could not append given item")?;
		G::Storage::put_raw(Self::key(), &new_val);
		Ok(())
	}
}

pub trait StorageMap<K: Codec, V: Codec> {
	/// The type that get/take returns.
	type Query;

	type Storage: Storage;

	// TODO TODO: maybe rename key_prefix
	fn prefix() -> &'static [u8];

	// Could we change this just asking for the default value ?
	fn from_optional_value_to_query(v: Option<V>) -> Self::Query;

	fn from_query_to_optional_value(v: Self::Query) -> Option<V>;

	fn key_for<KeyArg: Borrow<K>>(key: KeyArg) -> Vec<u8> {
		let mut full_key = Self::prefix().to_vec();
		key.borrow().encode_to(&mut full_key);
		full_key
	}
}

impl<K: Codec, V: Codec, G: StorageMap<K, V>> super::StorageMap<K, V> for G {
	/// The type that get/take return.
	type Query = G::Query;

	/// Get the prefix key in storage.
	fn prefix() -> &'static [u8] {
		G::prefix()
	}

	/// Does the value (explicitly) exist in storage?
	fn exists<KeyArg: Borrow<K>>(key: KeyArg) -> bool {
		G::Storage::exists(&G::key_for(key))
	}

	/// Load the value associated with the given key from the map.
	fn get<KeyArg: Borrow<K>>(key: KeyArg) -> Self::Query {
		G::from_optional_value_to_query(G::Storage::get(&G::key_for(key)))
	}

	/// Store a value to be associated with the given key from the map.
	fn insert<KeyArg: Borrow<K>, ValArg: Borrow<V>>(key: KeyArg, val: ValArg) {
		G::Storage::put(&G::key_for(key), &val.borrow())
	}

	/// Store a value under this key into the provided storage instance; this can take any reference
	/// type that derefs to `T` (and has `Encode` implemented).
	fn insert_ref<KeyArg: Borrow<K>, ValArg: ?Sized + Encode>(key: KeyArg, val: &ValArg)
		where V: AsRef<ValArg>
	{
		val.using_encoded(|b| G::Storage::put_raw(&G::key_for(key), b))
	}

	/// Remove the value under a key.
	fn remove<KeyArg: Borrow<K>>(key: KeyArg) {
		G::Storage::kill(&G::key_for(key))
	}

	/// Mutate the value under a key.
	fn mutate<KeyArg: Borrow<K>, R, F: FnOnce(&mut Self::Query) -> R>(key: KeyArg, f: F) -> R {
		// TODO TODO: avoid computing key everytime
		let mut val = G::get(key.borrow());

		let ret = f(&mut val);
		match G::from_query_to_optional_value(val) {
			Some(ref val) => G::insert(key, val),
			None => G::remove(key),
		}
		ret
	}

	/// Take the value under a key.
	fn take<KeyArg: Borrow<K>>(key: KeyArg) -> Self::Query {
		// TODO TODO: avoid computing of key multiple time
		let key = &G::key_for(key);
		let value = G::Storage::get(key);
		if value.is_some() {
			G::Storage::kill(key)
		}
		G::from_optional_value_to_query(value)
	}

	fn append<KeyArg: Borrow<K>, I: Encode>(key: KeyArg, items: &[I]) -> Result<(), &'static str>
		where V: EncodeAppend<Item=I>
	{
		let key = G::key_for(key);
		let encoded_value = G::Storage::get_raw(&key)
			.unwrap_or_else(|| {
				match G::from_query_to_optional_value(G::from_optional_value_to_query(None)) {
					Some(value) => value.encode(),
					None => vec![],
				}
			});

		let new_val = V::append(
			encoded_value,
			items,
		).ok_or_else(|| "Could not append given item")?;
		G::Storage::put_raw(&key, &new_val);
		Ok(())
	}
}

pub trait StorageLinkedMap<K: Codec, V: Codec> {
	/// The type that get/take returns.
	type Query;

	type Storage: Storage;

	fn prefix() -> &'static [u8];

	fn final_head_key() -> &'static [u8];

	fn from_optional_value_to_query(v: Option<V>) -> Self::Query;

	fn from_query_to_optional_value(v: Self::Query) -> Option<V>;

	fn key_for<KeyArg: Borrow<K>>(key: KeyArg) -> Vec<u8> {
		let mut full_key = Self::prefix().to_vec();
		key.borrow().encode_to(&mut full_key);
		full_key
	}
}

/// Linkage data of an element (it's successor and predecessor)
#[derive(Encode, Decode)]
pub struct Linkage<Key> {
	/// Previous element key in storage (None for the first element)
	pub previous: Option<Key>,
	/// Next element key in storage (None for the last element)
	pub next: Option<Key>,
}

impl<Key> Default for Linkage<Key> {
	fn default() -> Self {
		Self {
			previous: None,
			next: None,
		}
	}
}

/// A key-value pair iterator for enumerable map.
struct Enumerator<K: Codec, V: Codec, G: StorageLinkedMap<K, V>> {
	next: Option<K>,
	_phantom: PhantomData<(G, V)>,
}

impl<K: Codec, V: Codec, G: StorageLinkedMap<K, V>> Iterator for Enumerator<K, V, G> {
	type Item = (K, V);

	fn next(&mut self) -> Option<Self::Item> {
		let next = self.next.take()?;
		let next_full_key = G::key_for(&next);

		let (val, linkage): (V, Linkage<K>) = G::Storage::get(&next_full_key)
			.expect("previous/next only contain existing entires; we enumerate using next; entry exists; qed");

		self.next = linkage.next;
		Some((next, val))
	}
}

/// Update linkage when this element is removed.
///
/// Takes care of updating previous and next elements points
/// as well as updates head if the element is first or last.
fn remove_linkage<K: Codec, V: Codec, G: StorageLinkedMap<K, V>>(linkage: Linkage<K>) {
	let next_key = linkage.next.as_ref().map(|x| G::key_for(x));
	let prev_key = linkage.previous.as_ref().map(|x| G::key_for(x));

	if let Some(prev_key) = prev_key {
		// Retrieve previous element and update `next`
		let mut res = read_with_linkage::<K, V, G>(&*prev_key)
			.expect("Linkage is updated in case entry is removed; it always points to existing keys; qed");
		res.1.next = linkage.next;
		G::Storage::put(&*prev_key, &res);
	} else {
		// we were first so let's update the head
		write_head::<K, V, G>(linkage.next.as_ref());
	}

	if let Some(next_key) = next_key {
		// Update previous of next element
		let mut res = read_with_linkage::<K, V, G>(&*next_key)
			.expect("Linkage is updated in case entry is removed; it always points to existing keys; qed");
		res.1.previous = linkage.previous;
		G::Storage::put(&*next_key, &res);
	}
}

/// Read the contained data and it's linkage.
fn read_with_linkage<K, V, G>(key: &[u8]) -> Option<(V, Linkage<K>)>
where
	K: Codec,
	V: Codec,
	G: StorageLinkedMap<K, V>
{
	G::Storage::get(key)
}

/// Generate linkage for newly inserted element.
///
/// Takes care of updating head and previous head's pointer.
fn new_head_linkage<K, V, G>(key: &K) -> Linkage<K>
where
	K: Codec,
	V: Codec,
	G: StorageLinkedMap<K, V>
{
	if let Some(head) = read_head::<K, V, G>() {
		// update previous head predecessor
		{
			let head_key = G::key_for(&head);
			let (data, linkage) = read_with_linkage::<K, V, G>(&*head_key).expect(r#"
								head is set when first element is inserted and unset when last element is removed;
								if head is Some then it points to existing key; qed
							"#);
			G::Storage::put(&*head_key, &(data, Linkage {
				next: linkage.next.as_ref(),
				previous: Some(key),
			}));
		}
		// update to current head
		write_head::<K, V, G>(Some(key));
		// return linkage with pointer to previous head
		let mut linkage = Linkage::default();
		linkage.next = Some(head);
		linkage
	} else {
		// we are first - update the head and produce empty linkage
		write_head::<K, V, G>(Some(key));
		Linkage::default()
	}
}

/// Read current head pointer.
fn read_head<K, V, G>() -> Option<K>
where
	K: Codec,
	V: Codec,
	G: StorageLinkedMap<K, V>
{
	G::Storage::get(G::final_head_key())
}

/// Overwrite current head pointer.
///
/// If `None` is given head is removed from storage.
fn write_head<K, V, G>(head: Option<&K>)
where
	K: Codec,
	V: Codec,
	G: StorageLinkedMap<K, V>
{
	match head {
		Some(head) => G::Storage::put(G::final_head_key(), head),
		None => G::Storage::kill(G::final_head_key()),
	}
}

impl<K: Codec, V: Codec, G: StorageLinkedMap<K, V>> super::StorageLinkedMap<K, V> for G {
	type Query = G::Query;

	fn prefix() -> &'static [u8] {
		G::prefix()
	}

	fn exists<KeyArg: Borrow<K>>(key: KeyArg) -> bool {
		G::Storage::exists(&G::key_for(key.borrow()))
	}

	fn get<KeyArg: Borrow<K>>(key: KeyArg) -> Self::Query {
		G::from_optional_value_to_query(G::Storage::get(&G::key_for(key.borrow())))
	}

	fn insert<KeyArg: Borrow<K>, ValArg: Borrow<V>>(key: KeyArg, val: ValArg) {
		let key_for = &G::key_for(key.borrow());
		let linkage = match read_with_linkage::<K, V, G>(&key_for) {
			// overwrite but reuse existing linkage
			Some((_data, linkage)) => linkage,
			// create new linkage
			None => new_head_linkage::<K, V, G>(key.borrow()),
		};
		G::Storage::put(key_for, &(val.borrow(), linkage))
	}

	fn insert_ref<KeyArg: Borrow<K>, ValArg: ?Sized + Encode>(key: KeyArg, val: &ValArg) where V: AsRef<ValArg> {
		let key_for = &G::key_for(key.borrow());
		let linkage = match read_with_linkage::<K, V, G>(&key_for) {
			// overwrite but reuse existing linkage
			Some((_data, linkage)) => linkage,
			// create new linkage
			None => new_head_linkage::<K, V, G>(key.borrow()),
		};
		G::Storage::put(key_for, &(&val, &linkage))
	}

	fn remove<KeyArg: Borrow<K>>(key: KeyArg) {
		G::take(key.borrow());
	}

	fn mutate<KeyArg: Borrow<K>, R, F: FnOnce(&mut Self::Query) -> R>(key: KeyArg, f: F) -> R {
		let key_for = G::key_for(key.borrow());
		// TODO TODO: rewrite those 3 lines a bit
		let (mut val, _linkage) = read_with_linkage::<K, V, G>(&key_for)
			.map(|(data, linkage)| (G::from_optional_value_to_query(Some(data)), Some(linkage)))
			.unwrap_or_else(|| (G::from_optional_value_to_query(None), None));

		let ret = f(&mut val);
		match G::from_query_to_optional_value(val) {
			// TODO TODO: This could be optimised
			Some(ref val) => G::insert(key, val),
			None => G::remove(key),
		}
		ret
	}

	fn take<KeyArg: Borrow<K>>(key: KeyArg) -> Self::Query {
		let key = &G::key_for(key);

		let full_value: Option<(V, Linkage<K>)> = G::Storage::get(key);

		let value = match full_value {
			Some((data, linkage)) => {
				G::Storage::kill(key);
				remove_linkage::<K, V, G>(linkage);
				Some(data)
			},
			None => None,
		};

		G::from_optional_value_to_query(value)
	}

	// TODO TODO: we could implemented append by using a fixed size linkage.

	fn enumerate() -> Box<dyn Iterator<Item = (K, V)>> where K: 'static, V: 'static, Self: 'static {
		Box::new(Enumerator::<K, V, G> {
			next: read_head::<K, V, G>(),
			_phantom: Default::default(),
		})
	}
}

trait StorageDoubleMap<K1: Encode, K2: Encode, V: Codec> {
	/// The type that get/take returns.
	type Query;

	type Storage: StorageDoubleKey;

	/// Get the prefix key in storage.
	fn key1_prefix() -> &'static [u8];

	// Could we change this just asking for the default value ?
	fn from_optional_value_to_query(v: Option<V>) -> Self::Query;

	fn from_query_to_optional_value(v: Self::Query) -> Option<V>;

	/// Get the storage key used to fetch a value corresponding to a specific key.
	fn key_for<KArg1: Borrow<K1> + Encode + ?Sized>(k1: &KArg1) -> Vec<u8> {
		unimplemented!();
		// TODO TODO
	}
}

// TODO TODO:
// impl<K1: Encode, K2: Encode, V: Codec, G: StorageDoubleMap<K1, K2, V>> super::StorageDoubleMap<K1, K2, V> for G {
// 	/// The type that get/take returns.
// 	type Query;

// 	fn prefix() -> &'static [u8];

// 	fn key_for<KArg1, KArg2>(k1: &KArg1, k2: &KArg2) -> Vec<u8>
// 	where
// 		K1: Borrow<KArg1>,
// 		K2: Borrow<KArg2>,
// 		KArg1: ?Sized + Encode,
// 		KArg2: ?Sized + Encode;

// 	fn prefix_for<KArg1>(k1: &KArg1) -> Vec<u8> where KArg1: ?Sized + Encode, K1: Borrow<KArg1>;

// 	fn exists<KArg1, KArg2>(k1: &KArg1, k2: &KArg2) -> bool
// 	where
// 		K1: Borrow<KArg1>,
// 		K2: Borrow<KArg2>,
// 		KArg1: ?Sized + Encode,
// 		KArg2: ?Sized + Encode;

// 	fn get<KArg1, KArg2>(k1: &KArg1, k2: &KArg2) -> Self::Query
// 	where
// 		K1: Borrow<KArg1>,
// 		K2: Borrow<KArg2>,
// 		KArg1: ?Sized + Encode,
// 		KArg2: ?Sized + Encode;

// 	fn take<KArg1, KArg2>(k1: &KArg1, k2: &KArg2) -> Self::Query
// 	where
// 		K1: Borrow<KArg1>,
// 		K2: Borrow<KArg2>,
// 		KArg1: ?Sized + Encode,
// 		KArg2: ?Sized + Encode;

// 	fn insert<KArg1, KArg2, VArg>(k1: &KArg1, k2: &KArg2, val: &VArg)
// 	where
// 		K1: Borrow<KArg1>,
// 		K2: Borrow<KArg2>,
// 		V: Borrow<VArg>,
// 		KArg1: ?Sized + Encode,
// 		KArg2: ?Sized + Encode,
// 		VArg: ?Sized + Encode;

// 	fn remove<KArg1, KArg2>(k1: &KArg1, k2: &KArg2)
// 	where
// 		K1: Borrow<KArg1>,
// 		K2: Borrow<KArg2>,
// 		KArg1: ?Sized + Encode,
// 		KArg2: ?Sized + Encode;

// 	fn remove_prefix<KArg1>(k1: &KArg1) where KArg1: ?Sized + Encode, K1: Borrow<KArg1>;

// 	fn mutate<KArg1, KArg2, R, F>(k1: &KArg1, k2: &KArg2, f: F) -> R
// 	where
// 		K1: Borrow<KArg1>,
// 		K2: Borrow<KArg2>,
// 		KArg1: ?Sized + Encode,
// 		KArg2: ?Sized + Encode,
// 		F: FnOnce(&mut Self::Query) -> R;

// 	fn append<KArg1, KArg2, I>(
// 		k1: &KArg1,
// 		k2: &KArg2,
// 		items: &[I],
// 	) -> Result<(), &'static str>
// 	where
// 		K1: Borrow<KArg1>,
// 		K2: Borrow<KArg2>,
// 		KArg1: ?Sized + Encode,
// 		KArg2: ?Sized + Encode,
// 		I: codec::Encode,
// 		V: EncodeAppend<Item=I>;
// }
