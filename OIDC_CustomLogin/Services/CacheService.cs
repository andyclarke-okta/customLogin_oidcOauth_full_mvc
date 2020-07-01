using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Runtime.Caching;

namespace OIDC_CustomLogin.Services
{
    public  class CacheService
    {
        public ObjectCache cache;

        public CacheService()
        {
            this.cache = MemoryCache.Default;
        }

        public  void SavePasscode(string key, string passcode)
        {
 
            System.DateTimeOffset expiration = new DateTimeOffset(DateTime.UtcNow).AddMinutes(5);

            cache.Set(key, passcode, expiration);
        }

        public string GetPasscode(string key)
        {
            if (cache.Contains(key))
            {
                return cache[key].ToString();
            }

            return null;
        }

        public bool VerifyPasscode(string key, string passcode)
        {

            if (cache.Contains(key))
            {
                var userPasscode = cache[key].ToString();
                if (userPasscode == passcode)
                {
                    return true;
                }
            }

        return false;
        }

        public  bool DeletePasscode(string key)
        {

            if (cache.Contains(key))
            {
                cache.Remove(key);
                return true;
            }

            return false;
        }

    }
}