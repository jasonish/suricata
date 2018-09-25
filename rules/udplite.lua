function init(args)
   local needs = {}
   needs["packet"] = tostring(true)
   return needs
end

function match(args)

   -- Get the proto, make sure this is UDPLite.
   a, b, c, proto = SCPacketTuple()
   
   if proto ~= 136 then
      return 0
   end

   local coverage = SCUdpLiteCoverage()

   if coverage < -1 then
      -- This wasn't UDPLite, should have checked proto first.
      return 0
   end

   -- Alert if coverage is invalid.
   if coverage >= 1 and coverage <= 7 then
      return 1
   end
   
   return 0
end
