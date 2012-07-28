# A base module for collecting IP-related
# information from all kinds of platforms.
module Facter::Util::IP
  # A map of all the different regexes that work for
  # a given platform or set of platforms.
  REGEX_MAP = {
    :linux => {
      :netmask  => /Mask:([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)/
    },
    :bsd   => {
      :aliases  => [:openbsd, :netbsd, :freebsd, :darwin, :"gnu/kfreebsd", :dragonfly],
      :netmask  => /netmask\s+0x(\w{8})/
    },
    :sunos => {
      :netmask  => /netmask\s+(\w{8})/
    },
    :"hp-ux" => {
      :macaddress => /(\w{1,2}:\w{1,2}:\w{1,2}:\w{1,2}:\w{1,2}:\w{1,2})/,
      :netmask  => /.*\s+netmask (\S+)\s.*/
    },
    :windows => {
      :netmask  => /\s+Subnet Prefix:\s+\S+\s+\(mask ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\)/
    }
  }

  INTERFACE_MAP = {
    :linux => {
      :methods => {
        :ipaddress => {
          :ipv4 => {
            :ip => {
              :regex => '([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)',
              :exec  => '/sbin/ip addr show',
              :token => 'inet ',
            },
            :ifconfig => {
              :regex  => '([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)',
              :exec   => '/sbin/ifconfig',
              :token  => 'inet addr: ',
            },
          },
          :ipv6 => {
            :ip => {
              :regex => '((?![fe80|::1])(?>[0-9,a-f,A-F]*\:{1,2})+[0-9,a-f,A-F]{0,4})',
              :exec  => '/sbin/ip addr show',
              :token => 'inet6 ',
            },
            :ifconfig => {
              :regex  => '((?![fe80|::1])(?>[0-9,a-f,A-F]*\:{1,2})+[0-9,a-f,A-F]{0,4})',
              :exec   => '/sbin/ifconfig',
              :token  => 'inet6 addr: ',
            },
          },
        },
        :macaddress => {
          :ethernet => {
            :ip => {
              :exec  => '/sbin/ip addr show',
              :regex => '(\w{1,2}:\w{1,2}:\w{1,2}:\w{1,2}:\w{1,2}:\w{1,2})',
              :token => 'link/ether ',
            },
            :ifconfig => {
              :exec   => '/sbin/ifconfig',
              :regex  => '(\w{1,2}:\w{1,2}:\w{1,2}:\w{1,2}:\w{1,2}:\w{1,2})',
              :token  => '(?:ether|HWaddr) ',
            },
          },
        },
      },
    },
    :bsdlike => {
      :aliases  => [:openbsd, :netbsd, :freebsd, :darwin, :"gnu/kfreebsd", :dragonfly],
      :methods => {
        :ipaddress => {
          :ipv4 => {
            :ifconfig => {
              :regex  => '([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)',
              :exec  => '/sbin/ifconfig',
              :token => 'inet addr: ',
            },
          },
          :ipv6 => {
            :ifconfig => {
              :regex => '((?![fe80|::1])(?>[0-9,a-f,A-F]*\:{1,2})+[0-9,a-f,A-F]{0,4})',
              :exec  => '/sbin/ifconfig',
              :token => 'inet6 addr: ',
            },
          },
        },
        :macaddress => {
          :ethernet => {
            :ifconfig => {
              :exec  => '/sbin/ifconfig',
              :regex  => '(\w{1,2}:\w{1,2}:\w{1,2}:\w{1,2}:\w{1,2}:\w{1,2})',
              :token  => '(?:ether|HWaddr) ',
            },
          },
        },
      },
    },
    :sunos => {
      :methods => {
        :ipaddress => {
          :ipv4 => {
            :ifconfig => {
              :regex  => '([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)',
              :exec  => '/sbin/ifconfig',
              :token => 'inet ',
            },
          },
          :ipv6 => {
            :ifconfig => {
              :regex => '((?![fe80|::1])(?>[0-9,a-f,A-F]*\:{1,2})+[0-9,a-f,A-F]{0,4})',
              :exec  => '/sbin/ifconfig',
              :token => 'inet6 addr: ',
            },
          },
        },
        :macaddress => {
          :ethernet => {
            :ifconfig => {
              :exec  => '/sbin/ifconfig',
              :regex  => '(\w{1,2}:\w{1,2}:\w{1,2}:\w{1,2}:\w{1,2}:\w{1,2})',
              :token  => '(?:ether|HWaddr) ',
            },
          },
        },
      },
    },
    :"hp-ux" => {
      :methods => {
        :ipaddress => {
          :ipv4 => {
            :ifconfig => {
              :regex  => '([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)',
              :exec  => '/sbin/ifconfig',
              :token => 'inet ',
            },
          },
          :ipv6 => {
            :ifconfig => {
              :regex => '((?![fe80|::1])(?>[0-9,a-f,A-F]*\:{1,2})+[0-9,a-f,A-F]{0,4})',
              :exec  => '/sbin/ifconfig',
              :token => 'inet6 addr: ',
            },
          },
        },
        :macaddress => {
          :ethernet => {
            :lanscan => {
              :exec  => '/sbin/lanscan -a',
              :regex  => '(\w+)',
              :token  => '0x',
            },
          },
        },
      },
    },
    :aix => {
      :methods => {
        :ipaddress => {
          :ipv4 => {
            :ifconfig => {
              :regex  => '([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)',
              :exec  => '/sbin/ifconfig -a',
              :token => 'inet ',
            },
          },
          :ipv6 => {
            :ifconfig => {
              :regex => '((?![fe80|::1])(?>[0-9,a-f,A-F]*\:{1,2})+[0-9,a-f,A-F]{0,4})',
              :exec  => '/sbin/ifconfig -a',
              :token => 'inet6 ',
            },
          },
        },
        :macaddress => {
          :ethernet => {
            :ifconfig => {
              :exec  => '/sbin/ifconfig',
              :regex  => '(\w{1,2}:\w{1,2}:\w{1,2}:\w{1,2}:\w{1,2}:\w{1,2})',
              :token  => '(?:ether|HWaddr) ',
            },
          },
        },
      },
    },
    :windows => {
      :methods => {
        :ipaddress => {
          :ipv4 => {
            :netsh => {
              :regex  => '([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)',
              :exec  => "#{ENV['SYSTEMROOT']}/system32/netsh.exe interface ip show interface",
              :token => 'IP Address:\s+',
            },
          },
          :ipv6 => {
            :netsh => {
              :regex => /((?![fe80|::1])(?>[0-9,a-f,A-F]*\:{1,2})+[0-9,a-f,A-F]{0,4})/,
              :exec  => "#{ENV['SYSTEMROOT']}/system32/netsh.exe interface ipv6 show interface",
              :token => 'Address\s+',
            },
          },
        },
      },
    },
  }

  # Help find specific values in the INTERFACE_MAP nested hash to reduce boilerplate.
  def self.find_value(type, subtype)
    kernel = Facter.value(:kernel).downcase.to_sym
    unless map = INTERFACE_MAP[kernel] || INTERFACE_MAP.values.find { |tmp| tmp[:aliases] and tmp[:aliases].include?(kernel) }
      return []
    end
    return map[:methods][type.to_sym][subtype.to_sym]
  end

  # Extract the information from the output given a token, regex to parse and a regex of addresses to ignore.
  def self.get_item_after_token(output, token, regex, ignore=/^127\./)
    result = nil
    output.scan(/#{token}#{regex}/).each do |match|
      match = match.first
      unless match =~ ignore
        result = match
      end
    end
    result
  end

  def self.find_exec(type, subtype)
    exec = nil
    methods = self.find_value(type, subtype)
    methods.each do |name, method|
      # Strip back to just the file
      file = method[:exec].split(' ').first
      if FileTest.exists?(file)
        exec = method[:exec]
        break
      end
    end
    return exec
  end

  def self.find_entry(item, type, subtype, exec)
    entry = nil

    return entry unless methods = self.find_value(type, subtype)
    methods.each do |name, method|
      if method[:exec] == exec
        entry = method[item.to_sym]
      end
      break unless entry.nil?
    end
    entry
  end

  def self.ipaddress(interface=nil, subtype='ipv4', ignore=/^127\./)
    exec = Facter::Util::IP.find_exec('ipaddress', subtype)
    token = Facter::Util::IP.find_entry('token', 'ipaddress', subtype, exec)
    regex = Facter::Util::IP.find_entry('regex', 'ipaddress', subtype, exec)

    unless interface.nil?
      command = "#{exec} #{interface}"
    end
    output = Facter::Util::Resolution.exec(command)
    Facter::Util::IP.get_item_after_token(output, token, regex, ignore)
  end

  def self.macaddress(interface)
    macaddress = nil
    case Facter.value(:kernel)
    when :linux
      return nil unless output = File.read("/sys/class/net/#{interface}/address")
    else
      exec = Facter::Util::IP.find_exec('macaddress', 'ethernet')
      token = Facter::Util::IP.find_entry('token', 'macaddress', 'ethernet', exec)
      regex = Facter::Util::IP.find_entry('regex', 'macaddress', 'ethernet', exec)
      command = "#{exec} #{interface}"
      puts "e #{exec} t #{token} r #{regex}"

      output = Facter::Util::Resolution.exec(command)
      unless output =~ /interface #{interface} does not exist/
        macaddress = Facter::Util::IP.get_item_after_token(output, token, regex)
      end
    end
    macaddress
  end

  # Convert an interface name into purely alphanumeric characters.
  def self.alphafy(interface)
    interface.gsub(/[^a-z0-9_]/i, '_')
  end

  def self.convert_from_hex?(kernel)
    kernels_to_convert = [:sunos, :openbsd, :netbsd, :freebsd, :darwin, :"hp-ux", :"gnu/kfreebsd", :dragonfly]
    kernels_to_convert.include?(kernel)
  end

  def self.supported_platforms
    REGEX_MAP.inject([]) do |result, tmp|
      key, map = tmp
      if map[:aliases]
        result += map[:aliases]
      else
        result << key
      end
      result
    end
  end

  def self.get_interfaces
    case Facter.value(:kernel)
    when :linux
      # Linux lacks ifconfig -l so grub around in /proc/ for something to parse.
      interfaces = []
      output = File.read('/proc/net/dev')
      output.each_line do |line|
        line.match(/\w+\d*:/) do |m|
          interfaces << m.to_s.chomp(':') unless m.nil?
        end
      end
      puts interfaces
      interfaces.sort!
    when :freebsd, :netbsd, :openbsd, :dragonfly, :"gnu/kfreebsd", :darwin
      # Same command is used for ipv4 and ipv6
      exec = Facter::Util::IP.find_exec('ipaddress', 'ipv4')
      return [] unless output = Facter::Util::Resolution.exec("#{exec} -l")
      return output.scan(/\w+/)
    else
      return [] unless output = Facter::Util::IP.get_all_interface_output()

      # windows interface names contain spaces and are quoted and can appear multiple
      # times as ipv4 and ipv6
      return output.scan(/\s* connected\s*(\S.*)/).flatten.uniq if Facter.value(:kernel) == 'windows'

      # Our regex appears to be stupid, in that it leaves colons sitting
      # at the end of interfaces.  So, we have to trim those trailing
      # characters.  I tried making the regex better but supporting all
      # platforms with a single regex is probably a bit too much.
      output.scan(/^\S+/).collect { |i| i.sub(/:$/, '') }.uniq
    end
  end

  def self.get_all_interface_output()
    exec4 = Facter::Util::IP.find_exec('ipaddress', 'ipv4')
    exec6 = Facter::Util::IP.find_exec('ipaddress', 'ipv6')

    case Facter.value(:kernel)
    when 'HP-UX'
      output = %x{/bin/netstat -in | sed -e 1d}
    when 'windows'
      output = %x|#{exec4}|
      output += %x|#{exec6}|
    end
    output
  end


  def self.get_bonding_master(interface)
    if Facter.value(:kernel) != 'Linux'
      return nil
    end
    # We need ip instead of ifconfig because it will show us
    # the bonding master device.
    if not FileTest.executable?("/sbin/ip")
      return nil
    end
    # A bonding interface can never be an alias interface. Alias
    # interfaces do have a colon in their name and the ip link show
    # command throws an error message when we pass it an alias
    # interface.
    if interface =~ /:/
      return nil
    end
    regex = /SLAVE[,>].* (bond[0-9]+)/
      ethbond = regex.match(%x{/sbin/ip link show #{interface}})
    if ethbond
      device = ethbond[1]
    else
      device = nil
    end
    device
  end

  def self.get_interface_value(interface, label)
    tmp1 = []

    kernel = Facter.value(:kernel).downcase.to_sym

    # If it's not directly in the map or aliased in the map, then we don't know how to deal with it.
    unless map = REGEX_MAP[kernel] || REGEX_MAP.values.find { |tmp| tmp[:aliases] and tmp[:aliases].include?(kernel) }
      return []
    end

    # Pull the correct regex out of the map.
    regex = map[label.to_sym]

    # Linux changes the MAC address reported via ifconfig when an ethernet interface
    # becomes a slave of a bonding device to the master MAC address.
    # We have to dig a bit to get the original/real MAC address of the interface.
    bonddev = get_bonding_master(interface)
    if label == 'macaddress' and bonddev
      bondinfo = IO.readlines("/proc/net/bonding/#{bonddev}")
      hwaddrre = /^Slave Interface: #{interface}\n[^\n].+?\nPermanent HW addr: (([0-9a-fA-F]{2}:?)*)$/m
      value = hwaddrre.match(bondinfo.to_s)[1].upcase
    else
      output_int = get_output_for_interface_and_label(interface, label)
      output_int.each_line do |s|
        if s =~ regex
          value = $1
            if label == 'netmask' && convert_from_hex?(kernel)
              value = value.scan(/../).collect do |byte| byte.to_i(16) end.join('.')
            end
          tmp1.push(value)
        end
      end

      if tmp1
        value = tmp1.shift
      end
    end
  end

  def self.get_network_value(interface)
    require 'ipaddr'

    ipaddress = self.ipaddress(interface)
    netmask = get_interface_value(interface, "netmask")

    if ipaddress && netmask
      ip = IPAddr.new(ipaddress, Socket::AF_INET)
      subnet = IPAddr.new(netmask, Socket::AF_INET)
      network = ip.mask(subnet.to_s).to_s
    end
    network
  end

  def self.get_arp_value(interface)
    arp = Facter::Util::Resolution.exec("arp -en -i #{interface} | sed -e 1d")
    if arp =~ /^\S+\s+\w+\s+(\S+)\s+\w\s+\S+$/
     return $1
    end
  end
end
