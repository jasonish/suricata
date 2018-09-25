function init(args)
   local needs = {}
   return needs
end

function match(args)
   local a, b, c, d, sp, dp = SCPacketTuple()
   if sp == dp then
      return 1
   end
   return 0
end
