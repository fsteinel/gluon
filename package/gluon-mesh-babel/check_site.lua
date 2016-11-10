need_string_match('babel_mesh.prefix', '^[%x:]+/64$')
need_boolean('mesh_on_wan', false)

if need_string_match('next_node.ip4', '^%d+.%d+.%d+.%d+$', false) then
	need_string_match('prefix4', '^%d+.%d+.%d+.%d+/%d+$')
end

need_string_match('next_node.ip6', '^[%x:]+$')

need_string_match('next_node.mac', '^%x[02468aAcCeE]:%x%x:%x%x:%x%x:%x%x:%x%x$')


