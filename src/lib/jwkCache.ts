import NodeCache from "node-cache";

export interface KeyValueCache {
  /**
   * Get a cached key
   *
   * @param key cache key
   * @returns The value stored in the key
   */
  get: <V = string>(key: string) => Promise<V | undefined>;

  /**
   * Set a cached key
   *
   * @param key cache key
   * @param value An element to cache
   */
  set: <V = string>(key: string, value: V) => Promise<boolean>;
}

export class JwkCache implements KeyValueCache {
  /** Memory cache object */
  private cache: NodeCache;

  constructor(options?: NodeCache.Options) {
    this.cache = new NodeCache(options);
  }

  get<V = string>(key: string): Promise<V | undefined> {
    const value = this.cache.get<V>(key);
    return Promise.resolve(value);
  }

  set<V = string>(key: string, value: V): Promise<boolean> {
    const cached = this.cache.set<V>(key, value);
    return Promise.resolve(cached);
  }
}
