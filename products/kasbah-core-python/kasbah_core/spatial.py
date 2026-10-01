"""
Spatial Intelligence Module
Fei-Fei Li inspired spatial reasoning for AI detection
"""

from typing import Dict, List, Tuple


class SpatialIntelligence:
    """Validates spatial consistency in images/content"""
    
    def validate_geometry(self, features: Dict) -> Dict:
        """Check geometric consistency"""
        issues = []
        score = 1.0
        
        # Facial symmetry
        if 'left_eye_y' in features and 'right_eye_y' in features:
            asymmetry = abs(features['left_eye_y'] - features['right_eye_y'])
            if asymmetry > 5:
                issues.append(f'Eye asymmetry: {asymmetry}px')
                score -= 0.15
        
        # Facial proportions
        if 'face_width' in features and 'face_height' in features:
            ratio = features['face_width'] / max(features['face_height'], 1)
            if ratio < 0.45 or ratio > 0.85:
                issues.append(f'Unusual facial ratio: {ratio:.2f}')
                score -= 0.10
        
        return {'score': max(0, score), 'issues': issues}
    
    def validate_physics(self, features: Dict) -> Dict:
        """Check physics consistency"""
        issues = []
        score = 1.0
        
        # Gravity
        if features.get('gravity_direction') and features['gravity_direction'] != 'down':
            issues.append('Gravity inconsistency')
            score -= 0.20
        
        # Shadow directions
        shadow_dirs = features.get('shadow_directions', [])
        if len(set(shadow_dirs)) > 1:
            issues.append('Multiple shadow directions')
            score -= 0.25
        
        return {'score': max(0, score), 'issues': issues}
    
    def validate_lighting(self, features: Dict) -> Dict:
        """Check lighting consistency"""
        issues = []
        score = 1.0
        
        if features.get('has_objects') and not features.get('has_shadows'):
            issues.append('Objects without shadows')
            score -= 0.15
        
        if features.get('reflective_surfaces') and not features.get('has_reflections'):
            issues.append('Missing reflections')
            score -= 0.10
        
        return {'score': max(0, score), 'issues': issues}
    
    def analyze(self, image_features: Dict) -> Dict:
        """Complete spatial analysis"""
        geometry = self.validate_geometry(image_features)
        physics = self.validate_physics(image_features)
        lighting = self.validate_lighting(image_features)
        
        total_score = (geometry['score'] + physics['score'] + lighting['score']) / 3
        
        return {
            'is_spatially_consistent': total_score > 0.7,
            'confidence': total_score,
            'anomalies': geometry['issues'] + physics['issues'] + lighting['issues'],
            'breakdown': {
                'geometry': geometry,
                'physics': physics,
                'lighting': lighting
            }
        }


__all__ = ['SpatialIntelligence']
