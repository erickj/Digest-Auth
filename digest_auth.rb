#!/usr/bin/env ruby

# ruby Digest-Auth implementation example
# see http://tools.ietf.org/html/rfc2617
# copyright: Junction Networks
# author: Erick Johnson
# date: 3/11/2011

require 'digest/md5'

class DigestAuth
  attr_reader :username, :password, :uri, :method, :nonce, :realm, :qop, :cnonce

  # random algorithm I have chosen for demonstraction purposes
  def self.gen_client_nonce(extra_seed)
    seed = rand
    now = Time.now.to_f
    Digest::MD5.hexdigest("%s:%s:%s"%[seed,now,extra_seed])
  end

  def initialize(username, password, request_uri, method, realm, nonce, qop=nil, cnonce=nil)
    @username = username
    @password = password
    @uri      = request_uri
    @method   = method
    @realm    = realm
    @nonce    = nonce
    @qop      = qop

    @cnonce   = cnonce || DigestAuth.gen_client_nonce(nonce)
    @nonce_count = 1
  end

  def nonce_count
    "%08d"%@nonce_count.to_s(16)
  end

  def response
    responder = nil

    case self.qop.to_s.downcase.to_sym
    when :auth
      responder = QOP::Auth
    else
      # out of scope
    end

    responder.calc_response(self)
  end

  module QOP
    module Auth
      class << self

        def hA1(username, realm, password)
          str = [username, realm, password].join(":")
          Digest::MD5.hexdigest(str)
        end

        def hA2(meth, uri)
          str = [meth, uri].join(":")
          Digest::MD5.hexdigest(str)
        end

        def response(ha1, nonce, nc, cnonce, qop, ha2)
          str = [ha1, nonce, nc, cnonce, qop, ha2].join(":")
          Digest::MD5.hexdigest(str)
        end

        def calc_response(auth_request)
          ha1 = hA1(auth_request.username, auth_request.realm, auth_request.password)
          ha2 = hA2(auth_request.method, auth_request.uri)

          response(ha1,
                   auth_request.nonce,
                   auth_request.nonce_count,
                   auth_request.cnonce,
                   auth_request.qop,
                   ha2)
        end
      end
    end
  end
end

if $0 === __FILE__
  if (ARGV.length < 6) || (ARGV.find { |a| ['-h', '--help'].include?(a) })
    puts "Usage: %s <username> <password> <uri> <method> <realm> <nonce> [<qop> [<cnonce>]]"%$0
    puts "\t -h or --help print this message"
    exit 1
  end

  calculator = DigestAuth.new(*ARGV)

  puts
  puts "Here's your digest:"
  puts calculator.response
end
