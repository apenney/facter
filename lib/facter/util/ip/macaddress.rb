module Facter::Util::IP
  module Macaddress

  MAP = {
    :linux => {
      :ip => {
        :regex => '((\w{1,2}:){5,}\w{1,2})',
        :exec  => '/sbin/ip addr show',
        :token => '(?:ether|HWaddr)',
      },
      :ifconfig => {
        :regex  => '((\w{1,2}:){5,}\w{1,2})',
        :exec   => '/sbin/ifconfig',
        :token  => '(?:ether|HWaddr)',
      },
    },
    :bsdlike => {
      :aliases  => [:openbsd, :netbsd, :freebsd, :darwin, :"gnu/kfreebsd", :dragonfly],
      :ifconfig => {
        :regex  => '((\w{1,2}:){5,}\w{1,2})',
        :exec  => '/sbin/ifconfig',
        :token => '(?:ether|HWaddr)',
      },
    },
    :sunos => {
      :ifconfig => {
        :regex  => '(\w{2}:\w{2}:\w{2}:\w{2}:\w{2}:\w{2}$)',
        :exec  => '/usr/bin/netstat -np',
        :token => 'SPLA\s+',
      },
    },
    :"hp-ux" => {
      :ifconfig => {
        :regex  => '(0x\w+)',
        :exec  => '/usr/sbin/ifconfig',
        :token => '[\d+\/]+\s+',
        :ignore => '',
      },
    },
    :aix => {
      :ifconfig => {
        :regex  => '([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)',
        :exec  => '/sbin/ifconfig -a',
        :token => 'inet ',
        :ignore => '^127\.',
      },
    },
    :windows => {
      :netsh => {
        :regex  => '([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)',
        :exec  => "#{ENV['SYSTEMROOT']}/system32/netsh.exe interface ip show interface",
        :token => 'IP Address:\s+',
        :ignore => '^127\.',
      },
    },
  }

  def self.get(interface, ip_version='ipv4', ignore=nil)
    return nil unless Facter::Util::IP.supported_platforms(MAP)
    return nil unless ip_version == 'ipv4' || ip_version == 'ipv6'

    macaddress = nil
    kernel = Facter.value(:kernel).downcase.to_sym
    map = {}

    MAP.keys.each do |k|
      if k == kernel
        map = MAP[k]
      elsif MAP[k][:aliases]
        if MAP[k][:aliases].include?(kernel)
          map = MAP[k]
        end
      end
    end

    # This checks each exec in turn until one is found and then uses that
    # method for the rest of the matches.
    method = Facter::Util::IP.find_method(map)
    exec   = map[method.to_sym][:exec]
    token  = map[method.to_sym][:token]
    regex  = map[method.to_sym][:regex]
    if ignore.nil?
      ignore = map[method.to_sym][:ignore]
    end


    command = "#{exec}"
    command << " #{interface}" unless interface.nil?

    output = Facter::Util::Resolution.exec(command)
    return [] if output.nil?
    macaddress = Facter::Util::IP.find_token(output, token, regex, ignore)
  end

  end
end
