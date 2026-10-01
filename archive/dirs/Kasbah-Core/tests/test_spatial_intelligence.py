"""
Test Suite for Spatial Intelligence Module

Tests all validators:
- Geometry (symmetry, perspective, occlusion)
- Physics (gravity, collisions, motion)
- Lighting (shadows, reflections, sources)
- Depth
- Object Permanence
- World Model
"""

import pytest
import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from core.spatial_intelligence import (
    SpatialIntelligenceEngine,
    GeometryValidator,
    PhysicsValidator,
    LightingValidator,
    DepthValidator,
    ObjectPermanenceValidator,
    WorldModelValidator,
    SpatialAnomalies
)


class TestGeometryValidator:
    """Test geometry validation."""

    def test_facial_symmetry_perfect(self):
        """Test perfect facial symmetry."""
        validator = GeometryValidator()
        features = {
            'left_eye_y': 100,
            'right_eye_y': 100,
            'face_width': 150,
            'face_height': 200
        }
        score, issues = validator.validate_facial_symmetry(features)
        assert score > 0.8, "Should score high for symmetric face"
        assert len(issues) == 0, "Should have no issues"

    def test_facial_symmetry_asymmetric(self):
        """Test asymmetric facial symmetry."""
        validator = GeometryValidator()
        features = {
            'left_eye_y': 100,
            'right_eye_y': 120,  # 20px off
            'face_width': 100,
            'face_height': 300  # Unusual ratio
        }
        score, issues = validator.validate_facial_symmetry(features)
        assert score <= 0.75, "Should score reasonably for asymmetric face"
        assert len(issues) > 0, "Should detect issues"

    def test_perspective_normal(self):
        """Test normal perspective."""
        validator = GeometryValidator()
        features = {
            'vanishing_points': [(100, 50), (200, 75)],
            'line_convergence_angles': [30, 45]
        }
        score, issues = validator.validate_perspective(features)
        assert score > 0.9, "Should score high for normal perspective"

    def test_perspective_impossible(self):
        """Test impossible perspective."""
        validator = GeometryValidator()
        features = {
            'vanishing_points': [(10, 10)] * 5,  # Too many
            'line_convergence_angles': [2, 88]  # Extreme angles
        }
        score, issues = validator.validate_perspective(features)
        assert score <= 0.7, "Should score low for impossible perspective"
        assert len(issues) > 0, "Should detect issues"


class TestPhysicsValidator:
    """Test physics validation."""

    def test_gravity_realistic(self):
        """Test realistic gravity."""
        validator = PhysicsValidator()
        features = {
            'falling_objects': [
                {
                    'frame_positions': [
                        {'y': 100},
                        {'y': 110},
                        {'y': 125},  # Accelerating
                        {'y': 145}
                    ]
                }
            ]
        }
        score, issues = validator.validate_gravity(features)
        assert score > 0.7, "Should score reasonable for realistic gravity"

    def test_gravity_unrealistic(self):
        """Test unrealistic gravity."""
        validator = PhysicsValidator()
        features = {
            'falling_objects': [
                {
                    'frame_positions': [
                        {'y': 100},
                        {'y': 101},  # Very slow
                        {'y': 102},  # Not accelerating
                        {'y': 103}
                    ]
                }
            ]
        }
        score, issues = validator.validate_gravity(features)
        assert score <= 0.8, "Should score low for unrealistic gravity"

    def test_motion_realism_smooth(self):
        """Test smooth realistic motion."""
        validator = PhysicsValidator()
        features = {
            'tracked_motions': [
                {
                    'frame_deltas': [5, 5.1, 5.2, 5.0, 4.9]  # Smooth
                }
            ]
        }
        score, issues = validator.validate_motion_realism(features)
        assert score > 0.8, "Should score high for smooth motion"

    def test_motion_realism_jerky(self):
        """Test jerky unrealistic motion."""
        validator = PhysicsValidator()
        features = {
            'tracked_motions': [
                {
                    'frame_deltas': [1, 15, 2, 20, 3]  # Very jerky
                }
            ]
        }
        score, issues = validator.validate_motion_realism(features)
        assert score <= 0.9, "Should score lower for jerky motion"
        assert len(issues) > 0, "Should detect jerk issues"


class TestLightingValidator:
    """Test lighting validation."""

    def test_shadow_consistency_correct(self):
        """Test correct shadow consistency."""
        validator = LightingValidator()
        features = {
            'shadows': [
                {
                    'nearest_light': (200, 50),
                    'direction': (-1, 1),  # Away from light
                    'shadow_light_dot_product': -0.7  # Negative = away
                }
            ],
            'light_sources': [{'pos': (200, 50)}]
        }
        score, issues = validator.validate_shadow_consistency(features)
        assert score > 0.7, "Should score well for correct shadows"

    def test_shadow_consistency_wrong(self):
        """Test incorrect shadow direction."""
        validator = LightingValidator()
        features = {
            'shadows': [
                {
                    'nearest_light': (200, 50),
                    'direction': (1, 1),
                    'shadow_light_dot_product': 0.7  # Positive = toward light (wrong)
                }
            ],
            'light_sources': [{'pos': (200, 50)}]
        }
        score, issues = validator.validate_shadow_consistency(features)
        assert score <= 0.8, "Should score low for wrong shadows"
        assert len(issues) > 0, "Should detect issues"

    def test_light_source_temperature_consistent(self):
        """Test consistent light source temperature."""
        validator = LightingValidator()
        features = {
            'detected_lights': [
                {'color_temp': 5500},
                {'color_temp': 5600}
            ]
        }
        score, issues = validator.validate_light_sources(features)
        assert score > 0.9, "Should score high for consistent temps"

    def test_light_source_temperature_inconsistent(self):
        """Test inconsistent light source temperature."""
        validator = LightingValidator()
        features = {
            'detected_lights': [
                {'color_temp': 2700},  # Warm
                {'color_temp': 6500}   # Cool - 3800K difference
            ]
        }
        score, issues = validator.validate_light_sources(features)
        assert score <= 0.85, "Should score lower for inconsistent temps"


class TestObjectPermanenceValidator:
    """Test object permanence validation."""

    def test_temporal_tracking_consistent(self):
        """Test consistent object tracking."""
        validator = ObjectPermanenceValidator()
        features = {
            'tracked_objects': [
                {
                    'frames': [
                        {'size': 100},
                        {'size': 102},  # 2% change
                        {'size': 104},  # 2% change
                        {'size': 106}   # 2% change
                    ]
                }
            ]
        }
        score, issues = validator.validate_temporal_tracking(features)
        assert score > 0.8, "Should score well for consistent tracking"

    def test_temporal_tracking_inconsistent(self):
        """Test inconsistent object tracking."""
        validator = ObjectPermanenceValidator()
        features = {
            'tracked_objects': [
                {
                    'frames': [
                        {'size': 100},
                        {'size': 140},  # 40% change - unrealistic
                        {'size': 105},
                        {'size': 160}   # 50% change - very unrealistic
                    ]
                }
            ]
        }
        score, issues = validator.validate_temporal_tracking(features)
        assert score <= 0.8, "Should score low for inconsistent tracking"
        assert len(issues) > 0, "Should detect issues"


class TestWorldModelValidator:
    """Test world model validation."""

    def test_semantic_coherence_possible(self):
        """Test semantically coherent scene."""
        validator = WorldModelValidator()
        features = {
            'detected_objects': [
                {'label': 'beach'},
                {'label': 'ocean'},
                {'label': 'sand'}
            ]
        }
        score, issues = validator.validate_semantic_coherence(features)
        assert score > 0.8, "Should score well for coherent scene"

    def test_semantic_coherence_impossible(self):
        """Test semantically impossible scene."""
        validator = WorldModelValidator()
        features = {
            'detected_objects': [
                {'label': 'underwater'},
                {'label': 'fire'}  # Impossible together
            ]
        }
        score, issues = validator.validate_semantic_coherence(features)
        assert score <= 0.85, "Should score lower for impossible combination"
        assert len(issues) > 0, "Should detect impossible combination"

    def test_causal_consistency_strong(self):
        """Test strong causal relationships."""
        validator = WorldModelValidator()
        features = {
            'detected_events': [
                {
                    'apparent_causes': [
                        {'type': 'person_jumps', 'causality_to_effect': 0.9}
                    ],
                    'effects': [
                        {'type': 'person_airborne'}
                    ]
                }
            ]
        }
        score, issues = validator.validate_causal_consistency(features)
        assert score > 0.8, "Should score well for strong causality"

    def test_causal_consistency_weak(self):
        """Test weak causal relationships."""
        validator = WorldModelValidator()
        features = {
            'detected_events': [
                {
                    'apparent_causes': [
                        {'type': 'wind', 'causality_to_effect': 0.3}
                    ],
                    'effects': [
                        {'type': 'person_falls'}  # Weak connection
                    ]
                }
            ]
        }
        score, issues = validator.validate_causal_consistency(features)
        assert score <= 0.85, "Should score lower for weak causality"


class TestSpatialIntelligenceEngine:
    """Integration tests for Spatial Intelligence Engine."""

    def test_engine_initialization(self):
        """Test engine initializes correctly."""
        engine = SpatialIntelligenceEngine()
        assert engine.geometry is not None
        assert engine.physics is not None
        assert engine.lighting is not None
        assert engine.depth is not None

    def test_validate_image_authentic(self):
        """Test validation of authentic image."""
        engine = SpatialIntelligenceEngine()

        features = {
            'left_eye_y': 100,
            'right_eye_y': 100,
            'face_width': 160,
            'face_height': 200,
            'vanishing_points': [(150, 100), (200, 75)],
            'line_convergence_angles': [35, 45],
            'shadows': [{
                'nearest_light': (200, 50),
                'direction': (-1, 1),
                'shadow_light_dot_product': -0.8
            }],
            'light_sources': [{'pos': (200, 50)}],
            'detected_lights': [{'color_temp': 5500}],
            'detected_objects': [
                {'label': 'person'},
                {'label': 'chair'},
                {'label': 'room'}
            ]
        }

        score, anomalies = engine.validate_image(features)
        assert 0.7 < score <= 1.0, f"Authentic image should score high, got {score}"
        assert isinstance(anomalies, SpatialAnomalies)

    def test_validate_image_deepfake(self):
        """Test validation of synthesized/deepfake image."""
        engine = SpatialIntelligenceEngine()

        features = {
            'left_eye_y': 100,
            'right_eye_y': 130,  # Asymmetric
            'face_width': 80,  # Unusual
            'face_height': 250,
            'vanishing_points': [(50, 50), (150, 50), (250, 50), (350, 50)],  # Too many
            'line_convergence_angles': [1, 89],  # Extreme
            'shadows': [{
                'nearest_light': (100, 100),
                'direction': (1, 1),
                'shadow_light_dot_product': 0.8  # Points toward light (wrong)
            }],
            'light_sources': [{'pos': (100, 100)}],
            'detected_lights': [
                {'color_temp': 2700},
                {'color_temp': 6500}  # Huge mismatch
            ],
            'detected_objects': [
                {'label': 'underwater'},
                {'label': 'fire'}  # Impossible
            ]
        }

        score, anomalies = engine.validate_image(features)
        assert score <= 0.9, f"Deepfake should score lower, got {score}"
        assert len(anomalies.geometry_issues) > 0
        assert len(anomalies.lighting_issues) > 0
        assert len(anomalies.world_model_issues) > 0

    def test_validate_video_authentic(self):
        """Test validation of authentic video."""
        engine = SpatialIntelligenceEngine()

        features = {
            'falling_objects': [{
                'frame_positions': [
                    {'y': 100}, {'y': 109}, {'y': 124}, {'y': 145}
                ]
            }],
            'tracked_objects': [{
                'frames': [
                    {'size': 100},
                    {'size': 101},
                    {'size': 102},
                    {'size': 103}
                ]
            }],
            'tracked_motions': [
                {'frame_deltas': [5.0, 5.1, 5.0, 5.2, 4.9]}
            ],
            'detected_events': [{
                'apparent_causes': [
                    {'type': 'person_jumps', 'causality_to_effect': 0.95}
                ],
                'effects': [{'type': 'person_airborne'}]
            }]
        }

        score, anomalies = engine.validate_video(features)
        assert 0.7 < score <= 1.0, f"Authentic video should score high, got {score}"

    def test_validate_video_deepfake(self):
        """Test validation of deepfake video."""
        engine = SpatialIntelligenceEngine()

        features = {
            'falling_objects': [{
                'frame_positions': [
                    {'y': 100}, {'y': 101}, {'y': 102}, {'y': 103}
                ]
            }],
            'tracked_objects': [{
                'frames': [
                    {'size': 100},
                    {'size': 145},  # 45% jump
                    {'size': 105},
                    {'size': 160}   # 50% jump
                ]
            }],
            'tracked_motions': [
                {'frame_deltas': [1, 20, 2, 25, 3]}  # Very jerky
            ],
            'detected_events': [{
                'apparent_causes': [
                    {'type': 'wind', 'causality_to_effect': 0.2}
                ],
                'effects': [{'type': 'person_falls'}]
            }]
        }

        score, anomalies = engine.validate_video(features)
        assert score <= 0.9, f"Deepfake video should score lower, got {score}"
        assert len(anomalies.physics_issues) > 0
        assert len(anomalies.permanence_issues) > 0


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
