def a
  # ruleid: ruby.ssrf.request-derived-url
  URI.open(params[:url])
end

def b(target)
  # ruleid: ruby.ssrf.request-derived-url
  HTTParty.get(target)
end

def c
  # ok: ruby.ssrf.request-derived-url
  URI.open("https://api.example.test/v1")
end
