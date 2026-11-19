#!/usr/bin/env python3
import re
"""BlackFox C001.4B: native importer JSON -> cumulative exporter JSON.
Usage: python C001_4B_convert.py native.json texture_manifest.json output.json
Requires Python 3.9+; standard library only. Refuses ambiguous UVs.
"""
import json, math, pathlib, sys, os


def placement_transform(world):
    if (len(world) != 16 or not all(math.isfinite(value) for value in world)
            or any(abs(value - expected) > 1e-9
                   for value, expected in zip(world[12:], (0, 0, 0, 1)))):
        raise ValueError('unexpected 4x4 transform')
    # The bridge stores the linear part by rows, then translation in metres.
    return [*world[0:3], *world[4:7], *world[8:11], world[3], world[7], world[11], 1.0]


def solve3(a, b):
    a = [list(map(float, row)) + [float(v)] for row, v in zip(a, b)]
    for k in range(3):
        p = max(range(k, 3), key=lambda i: abs(a[i][k]))
        if abs(a[p][k]) < 1e-12:
            raise ValueError('degenerate UV basis')
        a[k], a[p] = a[p], a[k]
        v = a[k][k]
        for j in range(k, 4): a[k][j] /= v
        for i in range(3):
            if i == k: continue
            f = a[i][k]
            for j in range(k, 4): a[i][j] -= f*a[k][j]
    return [a[i][3] for i in range(3)]


class NonAffineMapping(ValueError):
    pass


def uvw_for_face(vertices, face, pairs, *, approximate=False):
    indices = face['outer']
    if len(indices) != len(pairs):
        raise ValueError('UV point count does not match face loop')
    p = [vertices[i] for i in indices]
    origin = p[0]
    e1 = [p[1][i]-origin[i] for i in range(3)]
    length = math.sqrt(sum(v*v for v in e1))
    if length < 1e-10: raise ValueError('zero-length face edge')
    eu = [v/length for v in e1]
    n = face['normal']
    nv = math.sqrt(sum(v*v for v in n))
    if nv < 1e-10: raise ValueError('zero face normal')
    n = [v/nv for v in n]
    ev = [n[1]*eu[2]-n[2]*eu[1], n[2]*eu[0]-n[0]*eu[2], n[0]*eu[1]-n[1]*eu[0]]
    xy = [[sum((v[i]-origin[i])*eu[i] for i in range(3)), sum((v[i]-origin[i])*ev[i] for i in range(3)), 1.0] for v in p]
    # Choose a noncollinear triple, not necessarily the first three points.
    triple = None
    for i in range(1,len(p)):
        for j in range(i+1,len(p)):
            area = (xy[i][0]*xy[j][1]-xy[j][0]*xy[i][1])
            if abs(area) > 1e-10: triple=(0,i,j); break
        if triple: break
    if not triple: raise ValueError('collinear face')
    a = [xy[i] for i in triple]
    u = solve3(a,[pairs[i][0] for i in triple]); v = solve3(a,[pairs[i][1] for i in triple])
    for xyrow, pair in zip(xy,pairs):
        for co, coeff in zip(pair,(u,v)):
            estimate=sum(x*y for x,y in zip(xyrow,coeff))
            if not approximate and abs(estimate-co)>1e-5*max(1,abs(co)):
                raise NonAffineMapping('non-affine UV mapping; cannot preserve exactly')
    gu=[u[0]*eu[i]+u[1]*ev[i] for i in range(3)]
    gv=[v[0]*eu[i]+v[1]*ev[i] for i in range(3)]
    return gu+[u[2]-sum(gu[i]*origin[i] for i in range(3))]+gv+[v[2]-sum(gv[i]*origin[i] for i in range(3))]


class FlatPlacementMismatch(ValueError):
    pass


def main(native_path, manifest_path, output_path, *, native=None):
    if native is None:
        native = json.loads(pathlib.Path(native_path).read_text(encoding='utf-8-sig'))
    manifest=json.loads(pathlib.Path(manifest_path).read_text(encoding='utf-8-sig'))
    if manifest.get('schema')!='BlackFoxTextureAssetsV1': raise ValueError('unexpected texture manifest schema')
    mats={m['material_index']:m for m in manifest['materials']}

    # Preserve original SketchUp material library and resolve embedded textures.
    source_materials = []
    for index, material in enumerate(native['model']['materials']):
        item = dict(material)
        if item.get('kind') == 'textured':
            if index not in mats:
                raise ValueError(f'material {index}: missing embedded texture')
            asset = mats[index]
            filename = asset['file']
            if filename is None:
                item.update(kind='solid', rgba=item.get('rgba', [192, 192, 192, 255]))
                item['missing_texture'] = item.pop('texture', None)
                source_materials.append(item)
                continue
            texture_path = (pathlib.Path(manifest_path).parent / filename).resolve()
            if not texture_path.is_file():
                raise FileNotFoundError(f'material {index}: {texture_path}')
            item['texture'] = str(texture_path)
        source_materials.append(item)

    # Source slots are archive-local and can be sparse in legacy SKP files.
    archive_materials = native.get('material_links')
    material_indices = (dict(archive_materials) if archive_materials is not None
                        else {i + 1: i for i in range(len(source_materials))})

    # BlackFox 0.9.7: preserve native PBR material records.
    pbr_manifest_path = pathlib.Path(manifest_path).resolve().parent / "blackfox_pbr_manifest.json"
    pbr_manifest = json.loads(pbr_manifest_path.read_text(encoding="utf-8-sig"))
    if pbr_manifest.get("schema") != "BlackFoxPbrAssetsV1":
        raise ValueError("Invalid PBR manifest schema")

    pbr_assets = {}
    for asset in pbr_manifest["textures"]:
        key = (asset["material_index"], asset["channel"])
        if key in pbr_assets:
            raise ValueError(f"Duplicate PBR asset {key}")
        pbr_assets[key] = asset

    source_pbr = []
    used_assets = set()
    seen_materials = set()

    for original in native["model"].get("features", {}).get("material_pbr", []):
        index = original["material"]
        if not isinstance(index, int) or not 0 <= index < len(source_materials):
            raise ValueError(f"Invalid PBR material index {index}")
        if index in seen_materials:
            raise ValueError(f"Duplicate PBR material index {index}")
        seen_materials.add(index)

        record = dict(original)

        for channel in ("metallic", "roughness", "normal", "occlusion"):
            texture = record.get(channel)
            if texture is None:
                continue

            key = (index, channel)
            asset = pbr_assets.get(key)
            if asset is None:
                raise ValueError(f"Missing PBR texture asset {key}")

            for field in ("id", "path", "file_name"):
                if asset[field] != texture[field]:
                    raise ValueError(f"PBR metadata mismatch {key}: {field}")

            filename = asset["file"]
            if pathlib.Path(filename).name != filename:
                raise ValueError(f"Invalid PBR asset filename {filename!r}")
            path = pbr_manifest_path.parent / filename
            data = path.read_bytes()
            import hashlib
            if not data.startswith(bytes([137, 80, 78, 71, 13, 10, 26, 10])):
                raise ValueError(f"Invalid PNG {path}")
            if len(data) != asset["bytes"]:
                raise ValueError(f"PBR byte count mismatch {key}")

            record[channel] = {
                "id": texture["id"],
                "path": texture["path"],
                "file_name": texture["file_name"],
                "asset_path": str(path.resolve())
            }
            used_assets.add(key)

        source_pbr.append(record)

    if used_assets != set(pbr_assets):
        raise ValueError(f"Unused PBR assets: {set(pbr_assets) - used_assets}")

    runs=native['mesh']['runs']; meta=native['model']['geometry_runs']; scene=native['mesh']['scene']
    if len(runs)!=len(meta): raise ValueError('geometry run count mismatch')

    # BlackFox v0.9.1: native layer-slot mapping.
    layer_catalogue = native['model']['layers']
    layer_links = native['mesh'].get('layer_links')

    if not isinstance(layer_links, list):
        raise ValueError('Missing v0.9.1 layer_links')

    slot_to_index = {}

    for link in layer_links:
        slot, index = link['slot'], link['index']
        if type(slot) is not int or type(index) is not int:
            raise ValueError('Invalid layer link')
        if not 0 <= index < len(layer_catalogue):
            raise ValueError('Layer index out of range')
        if slot in slot_to_index and slot_to_index[slot] != index:
            raise ValueError('Conflicting layer slot mapping')
        slot_to_index[slot] = index

    if not slot_to_index:
        raise ValueError('Empty layer mapping')

    def entity_layer(entity, context):
        index = entity.get('layer')
        if type(index) is not int or not 0 <= index < len(layer_catalogue):
            raise ValueError(f'{context}: invalid layer {index!r}')
        return layer_catalogue[index]['name']

    def instance_layer(node, context):
        slot = node.get('layer_slot')
        if type(slot) is not int or slot not in slot_to_index:
            raise ValueError(f'{context}: invalid layer slot {slot!r}')
        return layer_catalogue[slot_to_index[slot]]['name']

    objects=[]; loose=[]; defs=[]; instances=[]; counts={'textured_faces':0,'unpainted_faces':0,'groups':0,'components':0,'instances':0,'loose_runs':0}
    for ri,run in enumerate(runs):
        verts=run['vertices_m']; tex={f['pid']:f for f in meta[ri].get('textured_faces',[])}
        faces=[]
        for face in run['faces']:
            pid = face.get('pid')
            if type(pid) is not int or pid <= 0:
                raise ValueError(f'run {ri}: missing or invalid face PID {pid!r}')
            item={'source_face_pid':pid,'outer':face['outer'],'normal':face['normal'],'layer':entity_layer(face, f'run {ri} face'),'hidden':bool(face.get('hidden',False))}
            # Native material slots are 1-based; material definitions are 0-based.
            for side, native_key, prefix, uv_key in (
                ('front', 'front_material', '', 'uv_front'),
                ('back', 'back_material', 'back_', 'uv_back'),
            ):
                native_slot = face.get(native_key)
                if native_slot is None or native_slot == 0:
                    if side == 'front':
                        counts['unpainted_faces'] += 1
                    continue

                mat_index = material_indices.get(native_slot)
                if mat_index is None or not 0 <= mat_index < len(source_materials):
                    raise ValueError(f'run {ri} face {face["pid"]}: invalid {side} material slot {native_slot}')

                item[prefix + 'material_slot'] = mat_index + 1
                material = source_materials[mat_index]

                if material.get('kind') == 'textured':
                    size = material.get('applied_size_in')
                    if size is None:
                        raise ValueError(
                            f"Texture material {material['name']} has no applied size"
                        )

                    item[prefix + 'texture'] = {
                        'file': material['texture'],
                        'width_m': size[0] * 0.0254,
                        'height_m': size[1] * 0.0254,
                    }

                    uv = tex.get(face['pid'], {}).get(uv_key)
                    if uv is None:
                        raise ValueError(f'run {ri} face {face["pid"]}: missing {side} UVs')
                    try:
                        item[prefix + 'uvw'] = uvw_for_face(verts, face, uv)
                    except NonAffineMapping:
                        # IngeTrazo stores an affine UV transform for each face side.
                        item[prefix + 'uvw'] = uvw_for_face(verts, face, uv, approximate=True)
                        counts['approximated_uvs'] = counts.get('approximated_uvs', 0) + 1
                    if side == 'front':
                        counts['textured_faces'] += 1
                elif material.get('kind') != 'solid':
                    raise ValueError(f'unsupported source material kind: {material.get("kind")!r}')
            if face.get('holes'): item['holes'] = face['holes']
            faces.append(item)
        edges=[[e['v0'],e['v1']] for e in run['edges']]
        props=[{'hidden':e.get('hidden',False),'soft':e.get('soft',False),'smooth':e.get('smooth',False),'layer':entity_layer(e, f'run {ri} edge')} for e in run['edges']]
        # C001.5I2: preserve native welded curves and arc geometry.
        native_curves = run.get('curves', [])
        memberships = [[] for _ in native_curves]

        for edge_index, edge in enumerate(run['edges']):
            curve_index = edge.get('curve')
            if curve_index is None:
                continue
            if type(curve_index) is not int or not 0 <= curve_index < len(native_curves):
                raise ValueError(f'run {ri}: invalid curve index on edge {edge_index}')
            memberships[curve_index].append(edge_index)

        curves = []
        for curve_index, record in enumerate(native_curves):
            member_edges = memberships[curve_index]
            if len(member_edges) != record['members']:
                raise ValueError(
                    f'run {ri}: curve {curve_index} membership mismatch'
                )

            if not member_edges:
                raise ValueError(f'run {ri}: empty native curve {curve_index}')

            arc = record.get('arc')
            if arc is not None:
                radius = arc['radius_m']
                if radius <= 0:
                    raise ValueError(f'run {ri}: invalid arc radius')
                arc = dict(arc)
                arc.pop('pid', None)
                arc['x_axis_m'] = [v / radius for v in arc['x_axis_m']]
                arc['y_axis_m'] = [v / radius for v in arc['y_axis_m']]

            curves.append({'edges': member_edges, 'arc': arc})

        edge_pids=[e.get('pid', 0) for e in run['edges']]
        if any(type(pid) is not int or pid <= 0 for pid in edge_pids):
            raise ValueError(f'run {ri}: missing or invalid native edge PID')
        if len(set(edge_pids)) != len(edge_pids):
            raise ValueError(f'run {ri}: duplicate native edge PIDs')
        body={'vertices':verts,'edges':edges,'faces':faces,'edge_properties':props,'curves':curves,'source_edge_pids':edge_pids}
        nodes=[n for n in scene if n.get('run')==ri]
        # LAB03: unused definitions remain in the component library without
        # fabricating a visible scene instance. Root geometry must be placed.
        if not nodes and meta[ri].get('def_index') is None:
            raise ValueError(f'run {ri}: unplaced root geometry')
        if not nodes or all(n.get('is_group') is False for n in nodes):
            cid=f'Native2027_Component_Run{ri}'
            defs.append({'id':cid,'name':cid,**body})
            counts['components']+=1
            for n in nodes:
                transform = placement_transform(n['world'])
                instances.append({'definition_id':cid,'transform':transform,'layer':instance_layer(n, f'run {ri} component instance')})
                counts['instances']+=1
        elif len(nodes)==1 and nodes[0].get('is_group') is True:
            n = nodes[0]
            # Keep vertices and UVW local and carry the full placement separately.
            transform = placement_transform(n['world'])
            objects.append({'name':f'Native2027_Group_Run{ri}','transform':transform,'layer':instance_layer(n, f'run {ri} group'),**body});counts['groups']+=1
        elif len(nodes)==1 and nodes[0].get('is_group') is None:
            n=nodes[0];w=n['world']
            if any(abs(w[i]-t)>1e-9 for i,t in [(0,1),(1,0),(2,0),(4,0),(5,1),(6,0),(8,0),(9,0),(10,1),(3,0),(7,0),(11,0),(12,0),(13,0),(14,0),(15,1)]):
                raise ValueError('nonidentity loose geometry transform')
            loose.append({'name':f'Native2027_Loose_Run{ri}',**body});counts['loose_runs']+=1
        else: raise ValueError(f'run {ri} has unsupported placement types')
    def preserve_definition_identity(target, source, run_index):
        guid = source.get('guid')
        flag = source.get('flag')
        if guid and (not isinstance(guid, str) or re.fullmatch(r'[0-9a-fA-F]{32}', guid) is None):
            raise ValueError(f'run {run_index}: invalid original definition GUID')
        if type(flag) is not bool:
            raise ValueError(f'run {run_index}: invalid original definition flag')
        if guid:
            target['source_definition_guid'] = guid.lower()
        target['source_definition_flag'] = flag

    # C001.5H: restore verified native identity provenance.
    definitions_by_name = {d['name']: d['map_index'] for d in native['model']['definitions']}
    runs_by_definition = {
        r['def_index']: i
        for i, r in enumerate(native['model']['geometry_runs'])
        if r.get('def_index') is not None
    }
    if len(definitions_by_name) != len(native['model']['definitions']):
        raise ValueError('ambiguous native definition names')
    if len(runs_by_definition) != len(native['model']['definitions']):
        raise ValueError('ambiguous native definition ownership')

    used_instances = set()
    used_instance_guids = set()
    for instance in native['model']['instances']:
        definition = instance['definition']
        if definition not in definitions_by_name:
            raise ValueError(f'unknown native definition {definition!r}')
        run_index = runs_by_definition[definitions_by_name[definition]]
        translation = instance['translation_m']
        candidates = [
            node for node in scene
            if node.get('run') == run_index
            and all(abs(node['world'][axis] - translation[k]) < 1e-5
                    for k, axis in enumerate((3, 7, 11)))
            and node.get('is_group') == instance['is_group']
        ]
        if len(candidates) != 1:
            raise FlatPlacementMismatch(f'instance {instance["pid"]}: expected one matching scene node, got {len(candidates)}')
        node = candidates[0]
        node['_source_instance_pid'] = instance['pid']
        # Phase 2E: visibility belongs to the verified native occurrence.
        if type(instance.get('hidden')) is not bool:
            raise ValueError(f'instance {instance["pid"]}: missing native hidden flag')
        node['_source_hidden'] = instance['hidden']
        if type(instance.get('locked')) is not bool:
            raise ValueError(f'instance {instance["pid"]}: missing native locked flag')
        node['_source_locked'] = instance['locked']
        guid = instance.get('guid')
        if guid and (not isinstance(guid, str) or re.fullmatch(r'[0-9a-fA-F]{32}', guid) is None):
            raise ValueError(f"instance {instance['pid']}: invalid native GUID")
        if guid and guid != '0' * 32:
            guid = guid.lower()
            if guid in used_instance_guids:
                raise ValueError(f"Duplicate native instance GUID: {guid}")
            used_instance_guids.add(guid)
            node['_source_instance_guid'] = guid
        used_instances.add(instance['pid'])

    if len(used_instances) != len(native['model']['instances']):
        raise ValueError('native instance provenance incomplete')

    for ri, run in enumerate(runs):
        source_pids = run['vertex_pids']
        if len(source_pids) != len(run['vertices_m']):
            raise ValueError(f'run {ri}: vertex PID count mismatch')
        if len(set(source_pids)) != len(source_pids):
            raise ValueError(f'run {ri}: duplicate vertex PIDs')
        source_def_index = meta[ri].get('def_index')
        nodes = [n for n in scene if n.get('run') == ri]

        if source_def_index is None:
            matching = [o for o in loose if o['name'] == f'Native2027_Loose_Run{ri}']
            if len(matching) != 1:
                raise ValueError(f'run {ri}: loose provenance mismatch')
            matching[0]['source_vertex_pids'] = source_pids
        elif all(n.get('is_group') is False for n in nodes):
            matching = [d for d in defs if d['id'] == f'Native2027_Component_Run{ri}']
            if len(matching) != 1:
                raise ValueError(f'run {ri}: component provenance mismatch')
            matching[0]['source_vertex_pids'] = source_pids
            matching[0]['source_def_index'] = source_def_index

            source_definitions = [
                d for d in native['model']['definitions']
                if d.get('map_index') == source_def_index
            ]
            if len(source_definitions) != 1:
                raise ValueError(
                    f'run {ri}: expected one native component definition '
                    f'for index {source_def_index}'
                )

            source_behaviour = source_definitions[0].get('behaviour')
            required_behaviour = (
                'glues_to_surface', 'glue_plane', 'cuts_opening',
                'always_faces_camera', 'shadows_face_sun', 'extra'
            )
            if not isinstance(source_behaviour, dict):
                raise ValueError(f'run {ri}: missing native component behaviour')
            if any(k not in source_behaviour for k in required_behaviour):
                raise ValueError(f'run {ri}: incomplete native component behaviour')

            matching[0]['behaviour'] = {
                k: source_behaviour[k] for k in required_behaviour
            }
            # v0.9.4: Preserve original component definition name.
            matching[0]['name'] = source_definitions[0]['name']
            description = source_definitions[0].get('description', '')
            if not isinstance(description, str):
                raise ValueError(f'run {ri}: invalid native component description')
            matching[0]['source_description'] = description
            preserve_definition_identity(matching[0], source_definitions[0], ri)

            if len(nodes) != len([i for i in instances if i['definition_id'] == matching[0]['id']]):
                raise ValueError('component instance count mismatch')
            targets = [i for i in instances if i['definition_id'] == matching[0]['id']]
            for node, target in zip(nodes, targets):
                target['source_instance_pid'] = node['_source_instance_pid']
                target['hidden'] = node['_source_hidden']
                target['locked'] = node['_source_locked']
                target['source_instance_guid'] = node.get('_source_instance_guid')
        elif len(nodes) == 1 and nodes[0].get('is_group') is True:
            matching = [o for o in objects if o['name'] == f'Native2027_Group_Run{ri}']
            if len(matching) != 1:
                raise ValueError(f'run {ri}: group provenance mismatch')
            matching[0]['source_vertex_pids'] = source_pids
            matching[0]['source_def_index'] = source_def_index
            matching[0]['source_instance_pid'] = nodes[0]['_source_instance_pid']
            matching[0]['hidden'] = nodes[0]['_source_hidden']
            matching[0]['locked'] = nodes[0]['_source_locked']
            matching[0]['source_instance_guid'] = nodes[0].get('_source_instance_guid')
            # v0.9.4: Preserve original group definition name.
            source_definitions = [
                d for d in native['model']['definitions']
                if d.get('map_index') == source_def_index
            ]
            if len(source_definitions) != 1:
                raise ValueError(
                    f'run {ri}: expected one native group definition '
                    f'for index {source_def_index}'
                )
            matching[0]['name'] = source_definitions[0]['name']
            preserve_definition_identity(matching[0], source_definitions[0], ri)
        else:
            raise ValueError(f'run {ri}: unsupported native provenance')
    layers=[{'name':l['name'],'color':l['rgba'],'visible':l.get('visible',True)} for l in native['model']['layers']]
    # C001.5E: preserve supported native camera, scene and style metadata.
    model = native['model']

    def convert_camera(camera):
        if not isinstance(camera, dict):
            raise ValueError('missing native camera')
        required = ('eye_m', 'target_m', 'up')
        for key in required:
            if key not in camera:
                raise ValueError(f'native camera missing {key}')
        return {
            'eye_m': camera['eye_m'],
            'target_m': camera['target_m'],
            'up': camera['up'],
            'perspective': camera.get('perspective', True),
            'fov_deg': camera.get('fov_deg', 35.0),
            'parallel_height_m': camera.get('parallel_height_m', 3.0),
            'two_point_perspective': camera.get('two_point_perspective', False),
        }

    rendering_keys = (
        'face_style', 'xray', 'textures', 'edges', 'profiles', 'profiles_width',
        'background', 'sky', 'sky_color', 'ground', 'ground_color',
        'front_color', 'back_color', 'ambient_occlusion',
        'section_display', 'section_fill', 'section_fill_color',
        'section_cut_color', 'section_cut_width',
        'default_section_fill_style',
    )

    source_rendering = model.get('rendering') or {}
    converted_rendering = {
        key: source_rendering[key]
        for key in rendering_keys
        if source_rendering.get(key) is not None
    }

    styles = model.get('styles') or []
    active_style = model.get('active_style')
    style = None

    if active_style is not None:
        if not isinstance(active_style, int) or not 0 <= active_style < len(styles):
            raise ValueError('invalid active style index')
        style = styles[active_style]
        if converted_rendering.get('background') in (None, [0, 0, 0, 0]):
            style_background = (style.get('settings') or {}).get('background')
            if style_background is not None:
                converted_rendering['background'] = style_background

    thumbnail_manifest_path = os.environ.get(
        "BLACKFOX_SCENE_THUMBNAIL_MANIFEST"
    )
    thumbnail_assets = {}

    if thumbnail_manifest_path:
        import hashlib

        thumbnail_manifest_file = pathlib.Path(
            thumbnail_manifest_path
        ).resolve()

        thumbnail_manifest = json.loads(
            thumbnail_manifest_file.read_text(encoding="utf-8-sig")
        )

        if thumbnail_manifest.get("schema") != "BlackFoxSceneThumbnailsV1":
            raise ValueError("Unexpected scene thumbnail manifest schema")

        for asset in thumbnail_manifest["scenes"]:
            index = asset["scene_index"]

            if index in thumbnail_assets:
                raise ValueError(f"Duplicate thumbnail scene index {index}")

            if not isinstance(index, int) or isinstance(index, bool):
                raise ValueError("Invalid thumbnail scene index")

            if index < 0 or index >= len(model.get("scenes") or []):
                raise ValueError(f"Thumbnail scene index out of range: {index}")

            original = (model.get("scenes") or [])[index]

            if asset["scene_name"] != original["name"]:
                raise ValueError(f"Thumbnail scene name mismatch: {index}")

            if asset["file"] is None:
                if original.get("thumbnail") is not None:
                    raise ValueError(f"Missing original thumbnail: {index}")
                thumbnail_assets[index] = None
                continue

            filename = asset["file"]

            if pathlib.Path(filename).name != filename:
                raise ValueError("Thumbnail filename must be a basename")

            path = thumbnail_manifest_file.parent / filename
            data = path.read_bytes()

            if not data.startswith(bytes([137,80,78,71,13,10,26,10])):
                raise ValueError(f"Invalid scene thumbnail PNG: {index}")

            if len(data) != asset["bytes"]:
                raise ValueError(f"Thumbnail byte count mismatch: {index}")

            if original.get("thumbnail") != len(data):
                raise ValueError(f"Native thumbnail size mismatch: {index}")

            digest = hashlib.sha256(data).hexdigest()

            if digest.lower() != asset["sha256"].lower():
                raise ValueError(f"Thumbnail SHA256 mismatch: {index}")

            thumbnail_assets[index] = str(path.resolve())

        if len(thumbnail_assets) != len(model.get("scenes") or []):
            raise ValueError("Incomplete thumbnail manifest")

    original_scenes = model.get('scenes') or []
    converted_scenes = []

    for scene_index, scene_item in enumerate(original_scenes):
        converted_scenes.append({
            'name': scene_item['name'],
            'thumbnail_path': thumbnail_assets.get(scene_index),
            'description': scene_item.get('description') or '',
            'camera': convert_camera(scene_item['camera']),
            'saved': scene_item.get('saved'),
            'rendering': scene_item.get('rendering'),
            'shadows': scene_item.get('shadows'),
            'axes': scene_item.get('axes'),
            'style': scene_item.get('style'),
        })
        if output_path is None:
            converted_scenes[-1]['active_section_planes'] = scene_item.get('active_section_planes') or []
            converted_scenes[-1]['hidden_layers'] = scene_item.get('hidden_layers') or []

    source_active_layer = model.get('active_layer')
    if source_active_layer is not None and (
        type(source_active_layer) is not int
        or not 0 <= source_active_layer < len(layers)
    ):
        raise ValueError(
            f'Invalid source active layer index: {source_active_layer!r}'
        )
    output={'layers':layers,'objects':objects,'loose_geometry':loose,'component_definitions':defs,'component_instances':instances,'source_layer_links':layer_links,'source_materials':source_materials,'source_pbr':source_pbr,'source_active_layer':source_active_layer}

    # D4N.33: retain typed native dictionaries with stable provenance keys.
    # Native owner indices are converted before geometry is reordered.
    native_defs = model.get('definitions') or []
    native_runs = model.get('geometry_runs') or []
    native_instances = model.get('instances') or []
    source_dicts = []
    for group in model.get('dictionaries') or []:
        owner = group['owner']
        if owner == 'model' or owner == ['model']:
            normalized = ['model']
        elif isinstance(owner, list) and len(owner) == 2 and owner[0] == 'definition':
            idx = owner[1]
            if type(idx) is not int or not 0 <= idx < len(native_defs):
                raise ValueError(f'Invalid dictionary definition owner {owner!r}')
            normalized = ['definition_map', native_defs[idx]['map_index']]
        elif isinstance(owner, list) and len(owner) == 3 and owner[0] == 'face':
            run_idx, face_idx = owner[1:]
            if (type(run_idx) is not int or type(face_idx) is not int
                    or not 0 <= run_idx < len(runs)
                    or not 0 <= face_idx < len(runs[run_idx]['faces'])):
                raise ValueError(f'Invalid dictionary face owner {owner!r}')
            face_pid = runs[run_idx]['faces'][face_idx].get('pid')
            if type(face_pid) is not int or face_pid <= 0:
                raise ValueError(f'Invalid dictionary face PID for {owner!r}')
            # A PID is usable as an owner key only if it identifies one face.
            if sum(face.get('pid') == face_pid
                   for run in runs for face in run['faces']) != 1:
                raise ValueError(f'Ambiguous dictionary face PID {face_pid}')
            normalized = ['face_pid', face_pid]
        elif isinstance(owner, list) and len(owner) == 3 and owner[0] == 'instance':
            run_idx, placed_idx = owner[1:]
            if type(run_idx) is not int or type(placed_idx) is not int or not 0 <= run_idx < len(native_runs):
                raise ValueError(f'Invalid dictionary instance owner {owner!r}')
            # The native flattened instance catalogue must identify this placement.
            # For this importer, root placements are enumerated in the catalogue.
            if run_idx != len(native_runs) - 1 or not 0 <= placed_idx < len(native_instances):
                raise ValueError(f'Unsupported dictionary instance owner {owner!r}')
            normalized = ['instance_pid', native_instances[placed_idx]['pid']]
        else:
            raise ValueError(f'Unsupported dictionary owner {owner!r}')
        source_dicts.append({'owner': normalized, 'dictionaries': group['dictionaries']})
    output['source_dictionaries'] = source_dicts

    # Phase 2N.26: preserve original embedded SketchUp classification archives.
    # Hexadecimal payloads are validated before entering the export schema.
    source_classifications = []
    for record in native.get('source_classifications', []):
        if not isinstance(record, dict):
            raise ValueError('Invalid classification record')
        name = record.get('name')
        source_path = record.get('source_path')
        byte_count = record.get('bytes')
        data_hex = record.get('data_hex')
        if not isinstance(name, str) or not name:
            raise ValueError('Invalid classification name')
        if not isinstance(source_path, str):
            raise ValueError('Invalid classification source path')
        if type(byte_count) is not int or byte_count < 0:
            raise ValueError('Invalid classification byte count')
        if not isinstance(data_hex, str) or len(data_hex) != byte_count * 2:
            raise ValueError('Invalid classification hex length')
        try:
            archive = bytes.fromhex(data_hex)
        except ValueError as exc:
            raise ValueError('Invalid classification hex data') from exc
        if len(archive) != byte_count or not archive.startswith(b'PK'):
            raise ValueError('Invalid classification archive')
        source_classifications.append({
            'name': name,
            'source_path': source_path,
            'bytes': byte_count,
            'data_hex': data_hex,
        })
    output['source_classifications'] = source_classifications
    # BLACKFOX_PHASE_2P_WATERMARK_BRIDGE
    # Preserve native watermark metadata and embedded PNG bytes.
    def validate_watermark(wm):
        if not isinstance(wm, dict):
            raise ValueError('Invalid watermark record')

        required = (
            'name', 'source_file', 'background', 'tiled',
            'stretched', 'keep_aspect_ratio', 'position',
            'mask', 'blend', 'scale', 'time',
            'image_bytes', 'image_hex',
        )

        if any(key not in wm for key in required):
            raise ValueError('Incomplete watermark record')

        if not isinstance(wm['name'], str):
            raise ValueError('Invalid watermark name')

        if not isinstance(wm['source_file'], str):
            raise ValueError('Invalid watermark source path')

        for key in ('background', 'tiled', 'stretched',
                    'keep_aspect_ratio', 'mask'):
            if type(wm[key]) is not bool:
                raise ValueError(f'Invalid watermark {key}')

        for key in ('position', 'time'):
            if type(wm[key]) is not int or wm[key] < 0:
                raise ValueError(f'Invalid watermark {key}')

        for key in ('blend', 'scale'):
            if type(wm[key]) not in (int, float):
                raise ValueError(f'Invalid watermark {key}')
            if not math.isfinite(wm[key]):
                raise ValueError(f'Non-finite watermark {key}')

        count = wm['image_bytes']
        hex_data = wm['image_hex']

        if count is None and hex_data is None:
            return dict(wm)

        if type(count) is not int or count < 0:
            raise ValueError('Invalid watermark image byte count')

        if not isinstance(hex_data, str) or len(hex_data) != count * 2:
            raise ValueError('Invalid watermark image hex length')

        try:
            image = bytes.fromhex(hex_data)
        except ValueError as exc:
            raise ValueError('Invalid watermark image hex') from exc

        if len(image) != count:
            raise ValueError('Watermark image length mismatch')

        if image and not image.startswith(b'\x89PNG\r\n\x1a\n'):
            raise ValueError('Watermark image is not PNG')

        return dict(wm)

    style_watermarks = native.get('source_style_watermarks', [])
    current_watermarks = native.get('source_current_watermarks', [])

    if not isinstance(style_watermarks, list):
        raise ValueError('Invalid style watermark collection')

    if not isinstance(current_watermarks, list):
        raise ValueError('Invalid current watermark collection')

    converted_style_watermarks = []

    for entry in style_watermarks:
        if not isinstance(entry, dict):
            raise ValueError('Invalid style watermark entry')

        index = entry.get('style_index')
        if type(index) is not int or not 0 <= index < len(model.get('styles') or []):
            raise ValueError('Invalid watermark style index')

        watermarks = entry.get('watermarks')
        if not isinstance(watermarks, list):
            raise ValueError('Invalid style watermark list')

        converted_style_watermarks.append({
            'style_index': index,
            'watermarks': [validate_watermark(w) for w in watermarks],
        })

    output['source_style_watermarks'] = converted_style_watermarks
    output['source_current_watermarks'] = [
        validate_watermark(w) for w in current_watermarks
    ]

    # BLACKFOX_PHASE_2P_NATIVE_WATERMARK_SECTION_VALUE
    # Preserve the original 0x2CEE value without interpreting it.
    if 'source_native_watermark_section_value' in native:
        watermark_section_value = native['source_native_watermark_section_value']

        if watermark_section_value is not None:
            if (type(watermark_section_value) is not int
                    or not 0 <= watermark_section_value <= 0xFFFFFFFF):
                raise ValueError('Invalid native watermark section value')

        output['source_native_watermark_section_value'] = watermark_section_value

    # D4: preserve native document identity and current paint material.
    source_guid = model.get('model_guid')
    if source_guid is not None:
        if not isinstance(source_guid, str) or len(source_guid) != 32 or any(c not in '0123456789abcdefABCDEF' for c in source_guid):
            raise ValueError('Invalid native model GUID')
        output['source_model_guid'] = source_guid.lower()

    current_material = model.get('current_material')
    if current_material is not None:
        if isinstance(current_material, bool) or not isinstance(current_material, int) or not 0 <= current_material < len(source_materials):
            raise ValueError('Invalid native current material index')
        output['source_current_material'] = current_material
    # C001.5H3: preserve native SketchUp scene animation settings.
    animation = model.get('animation')

    if animation is not None:
        required = (
            'transitions',
            'transition_s',
            'delay_s',
            'loop_slideshow',
        )

        for key in required:
            if key not in animation:
                raise ValueError(f'missing native animation property: {key}')

        output['source_animation'] = {
            key: animation[key] for key in required
        }
    # C001.5I1: preserve original model units and display precision.
    units = model.get('units')
    if units is not None:
        required_units = (
            'length_format', 'length_unit', 'length_precision',
            'angle_precision', 'length_snap', 'length_snap_length',
            'angle_snap', 'snap_angle', 'suppress_units_display',
            'force_inch_display',
        )
        for key in required_units:
            if key not in units:
                raise ValueError(f'missing native unit property: {key}')

        optional_units = (
            'area_unit', 'volume_unit',
            'area_precision', 'volume_precision',
        )
        output['source_units'] = {
            key: units[key]
            for key in required_units + optional_units
            if key in units
        }

    # Preserve the original document's dimension preferences.
    defaults = model.get('dimension_defaults')
    if defaults is not None:
        output['source_dimension_defaults'] = defaults
    output['source_rendering'] = converted_rendering
    # Phase 2M: preserve the complete model-level SKP sun/shadow record.
    if model.get('shadows') is not None:
        if not isinstance(model['shadows'], dict):
            raise ValueError('Invalid model-level shadow record')
        output['source_shadows'] = model['shadows']

    if style is not None:
        output['source_style_name'] = style['name']
        output['source_style_description'] = ''

    if model.get('camera') is not None:
        output['camera'] = convert_camera(model['camera'])

    output['scenes'] = converted_scenes

    # C001.5F: restore root-level native construction lines.
    construction_lines = []

    for guide in model.get('guides') or []:
        if guide.get('def_index') is not None:
            raise ValueError(
                'Definition-owned construction lines are not supported yet'
            )

        construction_lines.append({
            'point': guide['point_m'],
            'direction': guide['direction'],
        })

    output['construction_lines'] = construction_lines

    # Native annotations retain their original anchors and ownership.
    # Preserve all native annotation properties except original annotation PIDs.
    # The Rust exporter allocates new PIDs and remaps anchor references.
    # C001.5H2: native construction points and section planes.
    # Definition ownership is preserved using the source definition index.
    native_geometry_entities = []

    for run in model.get('geometry_runs') or []:
        points = run.get('guide_points') or []
        sections = run.get('sections') or []
        active = run.get('active_section')

        if not points and not sections and active is None:
            continue

        section_pids = {s['pid'] for s in sections}

        if active is not None and active not in section_pids:
            raise ValueError(
                f"Active section PID {active} is missing from its owning run"
            )

        native_geometry_entities.append({
            'source_def_index': run.get('def_index'),
            'guide_points': points,
            'sections': sections,
            'active_section': active,
        })

    output['native_geometry_entities'] = native_geometry_entities
    output['native_dimensions'] = [
        {k: v for k, v in dimension.items() if k != 'pid'}
        for dimension in (model.get('dimensions') or [])
    ]
    # D4N61AE: preserve complete native radial/diametral metadata.
    # Do not strip edge PID: exporter must explicitly remap it.
    # Phase 2C: validate the edge-backed native radial records before
    # passing them to the IngeTrazo extension and the round-trip exporter.
    radial = native.get('native_radial_dimensions', [])
    if not isinstance(radial, list):
        raise ValueError('native_radial_dimensions must be a list')
    edge_pids = {e['pid'] for run in runs for e in run['edges']}
    if len(edge_pids) != sum(len(run['edges']) for run in runs):
        raise ValueError('duplicate source edge PID across geometry runs')
    seen_radial = set()
    required_radial = {
        'pid', 'def_index', 'edge', 'arc', 'diameter', 'leader',
        'text_override', 'font', 'aligned', 'arrow', 'layer',
        'material', 'hidden', 'casts_shadows', 'receives_shadows'
    }
    for record in radial:
        if not isinstance(record, dict):
            raise ValueError('radial dimension must be an object')
        missing = required_radial - record.keys()
        if missing:
            raise ValueError(f'radial dimension missing fields: {sorted(missing)}')
        pid = record['pid']
        if type(pid) is not int or pid <= 0 or pid in seen_radial:
            raise ValueError(f'invalid/duplicate radial dimension PID: {pid}')
        seen_radial.add(pid)
        if record['arc'] is not None:
            raise ValueError(f'radial dimension {pid}: embedded arc unsupported')
        if type(record['edge']) is not int or record['edge'] not in edge_pids:
            raise ValueError(f'radial dimension {pid}: edge PID unresolved')
        leader = record['leader']
        if (not isinstance(leader, list) or len(leader) != 2
                or any(type(x) not in (int, float) or not math.isfinite(x)
                       for x in leader)):
            raise ValueError(f'radial dimension {pid}: invalid leader')
        if type(record['diameter']) is not bool:
            raise ValueError(f'radial dimension {pid}: invalid diameter flag')
    output['native_radial_dimensions'] = [dict(record) for record in radial]
    output['native_texts'] = [
        {k: v for k, v in annotation.items() if k != 'pid'}
        for annotation in (model.get('texts') or [])
    ]

    # An absent selected scene remains absent; do not fabricate one.
    if model.get('active_scene') is not None:
        raise ValueError('active scene selection requires verified index mapping')
    output['source_geo_located'] = bool(model.get('geo_located', False))
    if output['source_geo_located'] and output_path is None:
        location = {key: value for key, _, value in model.get('attributes', [])}
        if 'Latitude' in location and 'Longitude' in location:
            output['source_location'] = {
                'latitude': location['Latitude'], 'longitude': location['Longitude'],
                'north_deg': math.degrees(location['GeoReferenceNorthAngle'])
                             if 'GeoReferenceNorthAngle' in location else None,
            }
    approximated_uvs = counts.get('approximated_uvs', 0)
    missing_textures = sum('missing_texture' in material for material in source_materials)
    if approximated_uvs or missing_textures:
        import logging
        logging.getLogger('blackfox_skp').warning(
            'SKP import approximated %d face-side UV mappings and used solid colours for %d missing textures.',
            approximated_uvs, missing_textures,
        )
    if output_path is None:
        return output
    if output.get('source_shadows') is None:
        output.pop('source_geo_located', None)
    pathlib.Path(output_path).parent.mkdir(parents=True,exist_ok=True)
    pathlib.Path(output_path).write_text(json.dumps(output,indent=2),encoding='utf-8')
    print('C001.4B CONVERSION COMPLETE:',json.dumps(counts,sort_keys=True))
    print('Output:',output_path)
    print('NOTE: geometry/material/UV bridge only; annotations, scenes and other metadata not yet round-tripped')

if __name__=='__main__':
    if len(sys.argv)!=4: sys.exit('Usage: python C001_4B_convert.py native.json texture_manifest.json output.json')
    try: main(*sys.argv[1:])
    except Exception as e: sys.exit(f'C001.4B ERROR: {e}')

