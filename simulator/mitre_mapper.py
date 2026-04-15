import os
import yaml

_MITRE_MAPPINGS = None

def _load_mappings():
    global _MITRE_MAPPINGS
    if _MITRE_MAPPINGS is not None:
        return _MITRE_MAPPINGS
        
    config_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'configs', 'mitre_mappings.yaml')
    try:
        with open(config_path, 'r') as f:
            _MITRE_MAPPINGS = yaml.safe_load(f)
    except FileNotFoundError:
        print(f"Warning: MITRE mappings config not found at {config_path}. Using empty mappings.")
        _MITRE_MAPPINGS = {}
    
    return _MITRE_MAPPINGS

def annotate_event_with_mitre(event_dict) -> dict:
    """
    Takes a log event dictionary and adds:
    - mitre_tactic: str (e.g., "Initial Access")
    - mitre_technique: str (e.g., "Spearphishing Link")
    - mitre_technique_id: str (e.g., "T1566.002")
    Returns enriched event dictionary.
    """
    mappings = _load_mappings()
    
    # Default values for events that might not map to a specific technique
    event_dict['mitre_tactic'] = 'None'
    event_dict['mitre_technique'] = 'None'
    event_dict['mitre_technique_id'] = 'None'
    
    attack_type = event_dict.get('attack_type', 'normal')
    if attack_type == 'normal' or attack_type not in mappings:
        return event_dict
        
    event_type = event_dict.get('event_type')
    
    mapping = mappings[attack_type].get(event_type)
    if mapping:
        event_dict['mitre_tactic'] = mapping.get('tactic', 'None')
        event_dict['mitre_technique'] = mapping.get('technique', 'None')
        event_dict['mitre_technique_id'] = mapping.get('technique_id', 'None')
        
    return event_dict
