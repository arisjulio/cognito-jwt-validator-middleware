import { JwkCache } from "../jwkCache";

describe("JwkCache", () => {
  const cache = new JwkCache();

  describe("set()", () => {
    it("should set a cached key", async () => {
      const cached = await cache.set("test_key", "test_value");
      expect(cached).toBeTruthy();
    });
  });

  describe("get()", () => {
    it("should get a cached key", async () => {
      const value = await cache.get("test_key");
      expect(value).toBe("test_value");
    });

    it("should not found a cached key", async () => {
      const value = await cache.get("invalid_key");
      expect(value).toBeUndefined();
    });
  });
});
