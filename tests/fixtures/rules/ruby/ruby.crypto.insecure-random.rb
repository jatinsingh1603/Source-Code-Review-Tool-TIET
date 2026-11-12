def a
  # ruleid: ruby.crypto.insecure-random
  rand(1_000_000)
end

def b
  # ruleid: ruby.crypto.insecure-random
  Random.rand(100)
end

def c
  # ok: ruby.crypto.insecure-random
  SecureRandom.hex(16)
end
