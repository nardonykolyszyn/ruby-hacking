# You must to install libpcap-dev package first.
# $ sudo apt install libpcap-dev
$VERBOSE=nil
require 'uri'
require 'net/dns'
require 'colorize'
require "terminfo"


TERM_WIDTH = TermInfo.screen_size[1]


require 'optparse'

OPTIONS = {}


# Attacks as lambdas
forward_lookup = lambda { |domain| puts Net::DNS::Resolver.start(domain) }
mx_lookup = lambda { |domain| puts Net::DNS::Resolver.start(domain,	Net::DNS::MX) }
all_lookup = lambda { |domain| puts Net::DNS::Resolver.start(domain.to_s,	Net::DNS::ANY).answer }
reverse_lookup = lambda { |domain| 	puts Net::DNS::Resolver.new.query(domain,	Net::DNS::PTR) }

ATTACKS = {
  "--forward-lookup" => forward_lookup,
  "--mx-lookup" => mx_lookup,
  "--all-lookup" => all_lookup,
  "--reverse-lookup" => reverse_lookup
}

# Parse options
parse = OptionParser.new do |ps|
  ps.banner = 'DNS resolvers'
  ps.separator('Devpolish0x0a'.center(TERM_WIDTH).red)
  ps.separator('='*TERM_WIDTH)
  ps.on('-u url', '--url=url', 'Domain URL e.g: google.com') do |url|
	  OPTIONS[:url] = url
  end
  
  ps.on('-aT attack', '--attack-type=attack', 'Attack type you want to use') do |attack|
    OPTIONS[:attack] = attack
  end
end

parse.parse!


if OPTIONS[:url].nil?
  raise ArgumentError, "Please provide an URL".red
elsif !ATTACKS.keys.include? OPTIONS[:attack]
  raise ArgumentError, "Please provide a valid attack type".red
end

# Execute attack
ATTACKS[OPTIONS.fetch(:attack)].call(OPTIONS.fetch(:url))