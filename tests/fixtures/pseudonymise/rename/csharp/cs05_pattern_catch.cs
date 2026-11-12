using System;

namespace Thapar.Core
{
    public class Inspector
    {
        public string Check(object payload)
        {
            if (payload is string text && text.Length > 3)
            {
                return text;
            }
            try
            {
                return payload.ToString();
            }
            catch (Exception failure)
            {
                return failure.Message;
            }
        }
    }
}
