function init(args)
   local needs = {}
   return needs
end

function match(args)

   -- TODO: Check that the proto is actually UDPLite before calling
   -- any UDPLite functions.

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
