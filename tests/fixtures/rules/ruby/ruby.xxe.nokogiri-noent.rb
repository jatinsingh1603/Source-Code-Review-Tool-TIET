def a(xml)
  # ruleid: ruby.xxe.nokogiri-noent
  Nokogiri::XML(xml) { |config| config.noent }
end

def b(xml)
  # ruleid: ruby.xxe.nokogiri-noent
  Nokogiri::XML(xml, nil, nil, Nokogiri::XML::ParseOptions::NOENT)
end

def c(xml)
  # ok: ruby.xxe.nokogiri-noent
  Nokogiri::XML(xml) { |config| config.nonet }
end
