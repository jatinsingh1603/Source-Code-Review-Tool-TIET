def a(host)
  # ruleid: ruby.injection.shell
  system("ping -c1 " + host)
end

def b
  # ruleid: ruby.injection.shell
  IO.popen("ls #{params[:dir]}")
end

def c
  # ok: ruby.injection.shell
  system("uptime")
end

def d(host)
  # ok: ruby.injection.shell
  system("ping", "-c1", host)
end
