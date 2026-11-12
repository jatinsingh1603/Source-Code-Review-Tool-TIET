def a
  # ruleid: ruby.path.file-access
  File.read(params[:path])
end

def b(name)
  # ruleid: ruby.path.file-access
  send_file("/srv/files/" + name)
end

def c
  # ok: ruby.path.file-access
  File.read("/srv/files/readme.txt")
end
