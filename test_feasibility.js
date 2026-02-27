
function chainFeasibility(assignments) {
    const out = [];
    const synthesizedFields = ['seed', 'secret', 'env_name', 'challenge', 'flag_prefix', 'username_prefix', 'key_len', 'node_name'];
    const synthesizedSet = new Set(synthesizedFields);
    const sequencerArtifacts = ['Knowledge(ip)'];
    const haveEffective = new Set(synthesizedFields);
    const haveArtifactsChain = new Set();
    const haveArtifactsSequencer = new Set(sequencerArtifacts);
    const haveFieldsChain = new Set();
    const haveFieldsSequencer = new Set(synthesizedFields);
    const haveArtifacts = new Set(sequencerArtifacts);
    const haveFields = new Set(synthesizedFields);

    const initOverride = {};

    if (!Array.isArray(assignments)) return out;
    for (let i = 0; i < assignments.length; i++) {
        const a = assignments[i] || {};

        const hasSplit = Array.isArray(a.requires) || Array.isArray(a.input_fields_required) || Array.isArray(a.input_fields);
        if (hasSplit) {
            const reqArtifactsRaw = Array.isArray(a.requires) ? a.requires.map(String) : [];
            const reqArtifacts = reqArtifactsRaw.filter(k => k && !synthesizedSet.has(k));
            const reqFieldsBase = Array.isArray(a.input_fields_required)
                ? a.input_fields_required.map(String)
                : (Array.isArray(a.input_fields) ? a.input_fields.map(String) : []);
            const reqFields = reqFieldsBase.concat(reqArtifactsRaw.filter(k => k && synthesizedSet.has(k)));
            const optFields = Array.isArray(a.input_fields_optional) ? a.input_fields_optional.map(String) : [];
            const optSet = new Set(optFields.filter(Boolean));

            const reqArtifactsEffective = reqArtifacts.filter(k => k && !optSet.has(k));
            const providedByChainArtifacts = reqArtifactsEffective.filter(k => k && haveArtifactsChain.has(k));
            const providedBySequencerArtifacts = reqArtifactsEffective.filter(k => k && haveArtifactsSequencer.has(k));
            const missingArtifacts = reqArtifactsEffective.filter(k => k && !haveArtifacts.has(k));

            let displayFields = reqFields.slice();
            displayFields = Array.from(new Set(displayFields.map(String).filter(Boolean)));

            const providedByChainFields = displayFields.filter(k => k && haveFieldsChain.has(k));
            const providedBySequencerFields = displayFields.filter(k => k && haveFieldsSequencer.has(k));
            const missingFields = reqFields.filter(k => k && !haveFields.has(k));

            const missing = missingArtifacts.concat(missingFields);
            out.push({
                ok: missing.length === 0,
                missing,
                missing_artifacts: missingArtifacts,
                missing_fields: missingFields,
                providing_artifacts_chain: providedByChainArtifacts,
                providing_artifacts_sequencer: providedBySequencerArtifacts,
                providing_fields_chain: providedByChainFields,
                providing_fields_sequencer: providedBySequencerFields,
            });
        } else {
            const reqEffective = Array.isArray(a.inputs) ? a.inputs.map(String) : [];
            const providingChain = reqEffective.filter(k => k && (haveArtifactsChain.has(k) || haveFieldsChain.has(k)));
            const providingSequencer = reqEffective.filter(k => k && (haveArtifactsSequencer.has(k) || haveFieldsSequencer.has(k)));
            const missing = reqEffective.filter(k => k && !haveEffective.has(k));
            out.push({
                ok: missing.length === 0,
                missing,
                missing_artifacts: [],
                missing_fields: [],
                providing_effective_chain: providingChain,
                providing_effective_sequencer: providingSequencer,
            });
        }

        const provEffective = Array.isArray(a.outputs) ? a.outputs.map(String) : [];
        provEffective.forEach(k => { if (k) haveEffective.add(k); });

        if (Array.isArray(a.produces)) {
            a.produces.map(String).forEach(k => {
                if (!k) return;
                haveArtifacts.add(k);
                haveArtifactsChain.add(k);
            });
        }
        if (Array.isArray(a.output_fields)) {
            a.output_fields.map(String).forEach(k => {
                if (!k) return;
                haveFields.add(k);
                haveFieldsChain.add(k);
            });
        }
    }
    return out;
}

const flagGen = {
    id: "fg1",
    type: "flag-generator",
    // No explicit I/O
};

const nodeGen = {
    id: "ng1",
    type: "flag-node-generator",
    input_fields_required: ["node_name"]
};

const res = chainFeasibility([flagGen, nodeGen]);
console.log(JSON.stringify(res, null, 2));
