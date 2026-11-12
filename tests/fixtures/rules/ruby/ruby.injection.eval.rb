def a
  # ruleid: ruby.injection.eval
  eval(params[:code])
end

def b(obj, src)
  # ruleid: ruby.injection.eval
  obj.instance_eval(src)
end

def c
  # ok: ruby.injection.eval
  eval("1 + 1")
end
