def a(p)
  # ruleid: ruby.crypto.weak-hash
  Digest::MD5.hexdigest(p)
end

def b(p)
  # ruleid: ruby.crypto.weak-hash
  Digest::SHA1.hexdigest(p)
end

def c(p)
  # ok: ruby.crypto.weak-hash
  Digest::SHA256.hexdigest(p)
end
