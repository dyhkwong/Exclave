/*
Copyright 2016 Aaron Hopkins and contributors

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at: http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.
*/

// modified from https://github.com/die-net/lrucache
package comm

import (
	"container/list"
	"sync"
	"time"
)

type LruCache struct {
	maxAge int64

	mu             sync.Mutex
	cache          map[any]*list.Element
	lru            *list.List
	updateAgeOnGet bool
}

func NewLruCache(maxAge int64, updateAgeOnGet bool) *LruCache {
	c := &LruCache{
		maxAge:         maxAge,
		lru:            list.New(),
		cache:          make(map[any]*list.Element),
		updateAgeOnGet: updateAgeOnGet,
	}
	return c
}

func (c *LruCache) Get(key any) (any, bool) {
	c.mu.Lock()
	le, ok := c.cache[key]
	if !ok {
		c.mu.Unlock()
		return nil, false
	}
	if c.maxAge > 0 && le.Value.(*entry).expires <= time.Now().Unix() {
		c.deleteElement(le)
		c.maybeDeleteOldest()
		c.mu.Unlock()
		return nil, false
	}
	c.lru.MoveToBack(le)
	entry := le.Value.(*entry)
	if c.maxAge > 0 && c.updateAgeOnGet {
		entry.expires = time.Now().Unix() + c.maxAge
	}
	c.mu.Unlock()
	return entry.value, true
}

func (c *LruCache) Set(key any, value any) {
	c.mu.Lock()
	expires := int64(0)
	if c.maxAge > 0 {
		expires = time.Now().Unix() + c.maxAge
	}
	if le, ok := c.cache[key]; ok {
		c.lru.MoveToBack(le)
		e := le.Value.(*entry)
		e.value = value
		e.expires = expires
	} else {
		e := &entry{key: key, value: value, expires: expires}
		c.cache[key] = c.lru.PushBack(e)
	}
	c.maybeDeleteOldest()
	c.mu.Unlock()
}

func (c *LruCache) Delete(key any) {
	c.mu.Lock()
	if le, ok := c.cache[key]; ok {
		c.deleteElement(le)
	}
	c.mu.Unlock()
}

func (c *LruCache) maybeDeleteOldest() {
	if c.maxAge > 0 {
		now := time.Now().Unix()
		for le := c.lru.Front(); le != nil && le.Value.(*entry).expires <= now; le = c.lru.Front() {
			c.deleteElement(le)
		}
	}
}

func (c *LruCache) deleteElement(le *list.Element) {
	c.lru.Remove(le)
	e := le.Value.(*entry)
	delete(c.cache, e.key)
}

type entry struct {
	key     any
	value   any
	expires int64
}
