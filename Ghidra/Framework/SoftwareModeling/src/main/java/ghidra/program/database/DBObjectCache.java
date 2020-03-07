/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
/*
 *
 */
package ghidra.program.database;

import java.lang.ref.ReferenceQueue;
import java.lang.ref.WeakReference;
import java.util.*;

import db.Record;
import ghidra.program.model.address.KeyRange;
import ghidra.util.datastruct.LongObjectHashtable;

/**
 * Generic cache implementation for objects that extend DatabaseObject.
 */
public class DBObjectCache<T extends DatabaseObject> {

	private LongObjectHashtable<KeyedSoftReference> hashTable;
	private ReferenceQueue<T> refQueue;
	private LinkedList<T> hardCache;
	private int hardCacheSize;
	private volatile int invalidateCount;

	/**
	 * Constructs a new DBObjectCache with a given hard cache size.  The hard cache size is
	 * the minimum number of objects to keep in the cache. Typically, the cache will contain
	 * more than this number, but the excess objects are subject to garbage collections
	 * @param hardCacheSize the minimum number of objects to keep in the cache.
	 */
	public DBObjectCache(int hardCacheSize) {
		this.hardCacheSize = hardCacheSize;
		hashTable = new LongObjectHashtable<KeyedSoftReference>();
		refQueue = new ReferenceQueue<T>();
		hardCache = new LinkedList<T>();
	}

	/**
	 * Retrieves the database object with the given key from the cache.
	 * @param key the key of the object to retrieve.
	 * @return the cached object or null if the object with that key is not currently cached.
	 */
	public synchronized T get(long key) {
		KeyedSoftReference ref = hashTable.get(key);
		if (ref != null) {
			T obj = ref.get();
			if (obj == null) {
				hashTable.remove(key);
			}
			else {
				if (obj.checkIsValid()) {
					addToHardCache(obj);
					return obj;
				}
				hashTable.remove(key);
			}
		}
		return null;
	}

	/**
	 * Retrieves the database object with the given record and associated key from the cache.
	 * This form should be used in conjunction with record iterators to avoid unnecessary
	 * record query during a possible object refresh.  To benefit from the record the cached
	 * object must implement the {@link DatabaseObject#refresh(Record)} method which by default
	 * ignores the record and simply calls {@link DatabaseObject#refresh()}.
	 * @param objectRecord the valid record corresponding to the object to be retrieved and possibly
	 * used to refresh the associated object if found in cache
	 * @return the cached object or null if the object with that key is not currently cached.
	 */
	public synchronized T get(Record objectRecord) {
		long key = objectRecord.getKey();
		KeyedSoftReference ref = hashTable.get(key);
		if (ref != null) {
			T obj = ref.get();
			if (obj == null) {
				hashTable.remove(key);
			}
			else {
				if (obj.checkIsValid(objectRecord)) {
					addToHardCache(obj);
					return obj;
				}
				hashTable.remove(key);
			}
		}
		return null;
	}

	/**
	 * Returns the number of objects currently in the cache.
	 */
	public int size() {
		return hashTable.size();
	}

	/**
	 * Sets the number of objects to protect against garbage collection.
	 * @param size the minimum number of objects to keep in the cache.
	 */
	public synchronized void setHardCacheSize(int size) {
		while (hardCache.size() > size) {
			hardCache.removeLast();
		}
		this.hardCacheSize = size;
	}

	/**
	 * Adds the given database object to the cache.
	 * @param data the object to add to the cache.
	 */
	void put(T data) {
		processQueue();
		long key = data.getKey();
		addToHardCache(data);
		KeyedSoftReference ref = new KeyedSoftReference(key, data, refQueue);
		hashTable.put(key, ref);
	}

	/**
	 * Returns an array of all the cached objects.
	 */
	public synchronized ArrayList<T> getCachedObjects() {
		ArrayList<T> list = new ArrayList<T>();
		processQueue();
		long[] keys = hashTable.getKeys();
		for (int i = 0; i < keys.length; i++) {
			KeyedSoftReference ref = hashTable.get(keys[i]);
			T obj = ref.get();
			if (obj != null) {
				list.add(obj);
			}
		}
		return list;
	}

	/**
	 * Delete all objects from hashTable whose key is contained
	 * within the specified keyRanges.
	 * @param keyRanges key ranges to delete
	 */
	public synchronized void delete(List<KeyRange> keyRanges) {
		hardCache.clear();
		processQueue();
		long rangesSize = getKeyRangesSize(keyRanges); // < 0 too many ranges
		if (rangesSize < 0 || rangesSize > hashTable.size()) {
			deleteLargeKeyRanges(keyRanges);
		}
		else {
			deleteSmallKeyRanges(keyRanges);
		}
	}

	/**
	 * Delete all objects from hashTable whose key is contained
	 * within the specified keyRanges.  Iteration over all
	 * keys contained within keyRanges will be performed.
	 * @param keyRanges key ranges to delete
	 */
	private void deleteSmallKeyRanges(List<KeyRange> keyRanges) {
		for (KeyRange range : keyRanges) {
			for (long key = range.minKey; key <= range.maxKey; key++) {
				KeyedSoftReference ref = hashTable.remove(key);
				if (ref != null) {
					DatabaseObject obj = ref.get();
					if (obj != null) {
						obj.setDeleted();
						ref.clear();
					}
				}
			}
		}
	}

	/**
	 * Delete all objects from hashTable whose key is contained
	 * within the specified keyRanges.  Iteration over all
	 * keys contained within hashTable will be performed.
	 * @param keyRanges key ranges to delete
	 */
	private void deleteLargeKeyRanges(List<KeyRange> keyRanges) {
		long[] keys = hashTable.getKeys();
		for (int i = 0; i < keys.length; i++) {
			if (keyRangesContain(keyRanges, keys[i])) {
				KeyedSoftReference ref = hashTable.remove(keys[i]);
				DatabaseObject obj = ref.get();
				if (obj != null) {
					obj.setDeleted();
					ref.clear();
				}
			}
		}
	}

	/**
	 * Return total number of keys covered by list of keyRanges.
	 * @param keyRanges
	 * @return number of keys, or -1 if more than Long.MAX_VALUE keys
	 */
	private long getKeyRangesSize(List<KeyRange> keyRanges) {
		long size = 0;
		for (KeyRange range : keyRanges) {
			size += range.length();
			if (size < 0) {
				return -1;
			}
		}
		return size;
	}

	private boolean keyRangesContain(List<KeyRange> keyRanges, long key) {
		for (KeyRange range : keyRanges) {
			if (range.contains(key)) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Marks all the cached objects as invalid.  Invalid objects will have to refresh themselves
	 * before they are allowed to be used. If an invalidated object cannot refresh itself, then
	 * the object is removed from the cache and discarded and the application can no longer use
	 * that instance of the object.
	 */
	public synchronized void invalidate() {
		hardCache.clear();
		processQueue();
		if (++invalidateCount <= 0) {
			invalidateCount = 1;
			long[] keys = hashTable.getKeys();
			for (int i = 0; i < keys.length; i++) {
				KeyedSoftReference ref = hashTable.get(keys[i]);
				DatabaseObject obj = ref.get();
				if (obj != null) {
					obj.setInvalid();
				}
			}
		}
	}

	/**
	 * Get the current invalidate counter value which corresponds to the number of time
	 * the entire cache has been invalidated.
	 * @return current invalidate counter value.
	 */
	int getInvalidateCount() {
		return invalidateCount;
	}

	/**
	 * Invalidates a range of objects in the cache.
	 * @param startKey the first key in the range to invalidate.
	 * @param endKey the last key in the range to invalidate.
	 */
	public synchronized void invalidate(long startKey, long endKey) {
		if (endKey - startKey < hashTable.size()) {
			for (long i = startKey; i <= endKey; i++) {
				invalidate(i);
			}
		}
		else {
			long[] keys = hashTable.getKeys();
			for (int i = 0; i < keys.length; i++) {
				if (keys[i] >= startKey && keys[i] <= endKey) {
					invalidate(keys[i]);
				}
			}
		}
	}

	/**
	 * Removes the object with the given key from the cache.
	 * @param key the key of the object to remove.
	 */
	public synchronized void delete(long key) {
		processQueue();
		KeyedSoftReference ref = hashTable.get(key);
		if (ref != null) {
			T obj = ref.get();
			if (obj != null) {
				obj.setDeleted();
				ref.clear();
			}
			hashTable.remove(key);
		}
	}

	/**
	 * Invalidates the object with given key.
	 * @param key the key of the object to invalidate.
	 */
	public synchronized void invalidate(long key) {
		processQueue();
		KeyedSoftReference ref = hashTable.get(key);
		if (ref != null) {
			T obj = ref.get();
			if (obj != null) {
				obj.setInvalid();
			}
		}
	}

	private void addToHardCache(T obj) {
		hardCache.addLast(obj);
		if (hardCache.size() > hardCacheSize) {
			hardCache.removeFirst();
		}
	}

	// we know the cast is safe--we put them in there
	@SuppressWarnings("unchecked")
	private void processQueue() {
		KeyedSoftReference ref;
		while ((ref = (KeyedSoftReference) refQueue.poll()) != null) {
			long key = ref.getKey();
			KeyedSoftReference oldValue = hashTable.remove(key);

			if (oldValue != null && oldValue != ref) {
				// we have put another item in the cache with the same key.  Further, we
				// removed the item, but the garbage collector had not put the item on the
				// reference queue until after we added a new reference to the cache.
				// We want to keep the last value that was added, as it has not been deleted.
				hashTable.put(key, oldValue);
			}
		}
	}

	private class KeyedSoftReference extends WeakReference<T> {
		private long key;

		KeyedSoftReference(long key, T obj, ReferenceQueue<T> queue) {
			super(obj, queue);
			this.key = key;
		}

		long getKey() {
			return key;
		}
	}

	public synchronized void keyChanged(long oldKey, long newKey) {
		processQueue();

		KeyedSoftReference ref = hashTable.remove(oldKey);
		if (ref != null) {
			hashTable.put(newKey, ref);
			T t = ref.get();
			if (t != null) {
				t.setInvalid();
			}
		}
	}
}
