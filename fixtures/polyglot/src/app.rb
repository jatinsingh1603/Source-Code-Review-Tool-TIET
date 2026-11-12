require 'sinatra'

get '/eval' do
  eval(params[:expr])  # PG-VULN-006
end
