require "../src/sodium"

if ARGV.empty?
  puts "Help select Pwhash ops/mem limits for your application."
  puts "Usage: #{PROGRAM_NAME} time_min [time_max] [mem_max]"
  puts "\ttime is in seconds"
  puts "\tmem is in bytes"
  exit 1
end

time_min = ARGV.shift?.try &.to_f || 0.1
time_limit = if t = ARGV.shift?
               t.to_f
             else
               time_min * 4
             end
mem_limit = (ARGV.shift?.try &.to_i || (Sodium::Pwhash::MEMLIMIT_MAX)).to_u64
pwhash = Sodium::Pwhash.new
pass = "1234"

# data = Array(Array({UInt64, UInt64, Float64})).new
header = ["      "]
data = [header]

def bytes_str(b)
  suffix = if b >= 1024*1024
             b /= (1024*1024)
             "M"
           elsif b >= 1024
             b = b / 1024
             "K"
           else
             ""
           end
  "%5d#{suffix}" % b
end

pwhash.memlimit = Sodium::Pwhash::MEMLIMIT_MIN
loop do
  pwhash.opslimit = Sodium::Pwhash::OPSLIMIT_MIN
  row = ["%5dK" % (pwhash.memlimit / 1024)]
  data << row

  loop do
    # p pwhash
    t = Time.measure { pwhash.create pass }.to_f
    ostr = "%7d" % pwhash.opslimit
    header << ostr if data.size == 2
    if t >= time_min
      mstr = bytes_str pwhash.memlimit
      #      mstr = "%5dK" % (pwhash.memlimit / 1024)
      tstr = "%6.3fs" % t
      row << tstr
      s = String.build do |sb|
        sb << "mem_limit "
        sb << mstr
        sb << "    ops_limit "
        sb << ostr
        sb << "    "
        sb << tstr
      end
      puts s
    else
      row << "       "
    end

    break if t >= time_limit
    pwhash.opslimit *= 4
  end
  row << "" # puts | on the end
  puts ""

  break if pwhash.memlimit >= mem_limit
  break if pwhash.opslimit == Sodium::Pwhash::OPSLIMIT_MIN # Couldn't get past 1 iteration before going over time.
  pwhash.memlimit *= 4
end
# header << "Ops limit"
data << ["Memory"]

# Quick n dirty sparse table.
puts "Ops Limit --->"
data.each do |row|
  puts row.join(" | ")
end
