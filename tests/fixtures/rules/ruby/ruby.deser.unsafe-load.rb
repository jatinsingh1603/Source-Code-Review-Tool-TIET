def a
  # ruleid: ruby.deser.unsafe-load
  Marshal.load(params[:state])
end

def b(blob)
  # ruleid: ruby.deser.unsafe-load
  YAML.load(blob)
end

def c(blob)
  # ok: ruby.deser.unsafe-load
  YAML.safe_load(blob)
end

def d(blob)
  # ok: ruby.deser.unsafe-load
  JSON.parse(blob)
end
