require "open-uri"
require "openssl"

User.where("name = '#{params[:name]}'")

q = params[:q]
system("ls #{q}")

n = params[:n]
render html: ("hi " + n).html_safe

f = params[:f]
File.read(Rails.root.join("pub", f))

u = params[:url]
URI.open(u)

nxt = params[:next]
redirect_to nxt

c = params[:code]
eval(c)

d = params[:data]
Marshal.load(d)

x = params[:doc]
Nokogiri::XML(x)

Digest::MD5.hexdigest("pw")

token = rand(1000000)

http.verify_mode = OpenSSL::SSL::VERIFY_NONE

t = params[:t]
ERB.new(t).result(binding)
