#!/usr/bin/env ruby

require 'rmagick'
require 'base64'
include Magick

img=Image.read("image.png")[0]
flip=img.flip
flip.write("image2.png")
b64flip='<img src="data:img/png;base64,'+Base64.encode64(flip.to_blob).strip+'">'
puts b64flip
exit
