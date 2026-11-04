require "securerandom"
require "open-uri"
require "openssl"

User.where("name = ?", "static")

File.read(Rails.root.join("pub", "index.html"))

URI.open("https://example.com/feed")

redirect_to root_path

eval("1 + 2")

static_blob = "static"
Marshal.load(static_blob)

Nokogiri::XML("<root/>")

Digest::SHA256.hexdigest("pw")

token = SecureRandom.hex(16)

http.verify_mode = OpenSSL::SSL::VERIFY_PEER

ERB.new("<p>hi</p>").result(binding)


qq = params[:qq]
system("ls", Shellwords.escape(qq))

nn = params[:nn]
render html: h(nn)
