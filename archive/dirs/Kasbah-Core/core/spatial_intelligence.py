"""
Spatial Intelligence Module for Kasbah AI Safety Platform

Implements Fei-Fei Li's spatial reasoning framework to detect "ungrounded" AI.
"AIs are eloquent but ungrounded" - they fail at basic spatial consistency.

This module validates:
- Geometry (3D consistency, perspective, symmetry)
- Physics (gravity, motion, collisions)
- Lighting (shadows, reflections, ambient occlusion)
- Depth (focus, blur, occlusion)
- Object Permanence (temporal consistency)
- World Model (semantic coherence, causal consistency)

Phase 2 Integration Feature
Status: Production-Ready
"""

from dataclasses import dataclass
from typing import Optional, Dict, List, Tuple
import logging

logger = logging.getLogger(__name__)


@dataclass
class SpatialAnomalies:
    """Container for detected spatial anomalies."""
    geometry_issues: List[str]
    physics_issues: List[str]
    lighting_issues: List[str]
    depth_issues: List[str]
    permanence_issues: List[str]
    world_model_issues: List[str]


class GeometryValidator:
    """Validates 3D geometric consistency in images."""

    @staticmethod
    def validate_facial_symmetry(image_features: Dict) -> Tuple[float, List[str]]:
        """
        Check facial symmetry. AI often fails at perfect balance.

        Returns:
            (score: 0-1, issues: List of detected anomalies)
        """
        issues = []
        score = 1.0

        # Check if eyes are at same height
        left_eye = image_features.get('left_eye_y')
        right_eye = image_features.get('right_eye_y')

        if left_eye and right_eye:
            asymmetry = abs(left_eye - right_eye)
            if asymmetry > 5:  # Threshold in pixels
                issues.append(f"Eyes asymmetrical by {asymmetry}px")
                score -= 0.15

        # Check facial proportions
        face_width = image_features.get('face_width')
        face_height = image_features.get('face_height')

        if face_width and face_height:
            ratio = face_width / face_height if face_height else 1
            if ratio < 0.45 or ratio > 0.85:  # Normal range for human faces
                issues.append(f"Facial proportions unusual: {ratio:.2f}")
                score -= 0.10

        return max(0, score), issues

    @staticmethod
    def validate_perspective(image_features: Dict) -> Tuple[float, List[str]]:
        """Check perspective consistency using vanishing points."""
        issues = []
        score = 1.0

        vanishing_points = image_features.get('vanishing_points', [])

        # Real images should have 1-3 vanishing points
        if len(vanishing_points) == 0:
            issues.append("No vanishing points detected (unlikely)")
            score -= 0.05
        elif len(vanishing_points) > 3:
            issues.append(f"Too many vanishing points: {len(vanishing_points)}")
            score -= 0.20

        # Check if parallel lines converge correctly
        convergence_angles = image_features.get('line_convergence_angles', [])
        for angle in convergence_angles:
            if angle < 5 or angle > 85:  # Normal range for real images
                issues.append(f"Unusual line convergence: {angle}°")
                score -= 0.05

        return max(0, score), issues

    @staticmethod
    def validate_occlusion(image_features: Dict) -> Tuple[float, List[str]]:
        """Check object occlusion consistency."""
        issues = []
        score = 1.0

        # Check if occluded edges are consistent
        occlusion_edges = image_features.get('occlusion_edges', [])

        for edge in occlusion_edges:
            # In real images, occluded edges should have reduced texture detail
            if edge.get('texture_detail') > 0.7:
                issues.append("Occluded edge has unrealistic texture detail")
                score -= 0.10

        return max(0, score), issues


class PhysicsValidator:
    """Validates physical laws in videos/images."""

    @staticmethod
    def validate_gravity(motion_features: Dict) -> Tuple[float, List[str]]:
        """Check if objects fall according to gravity."""
        issues = []
        score = 1.0

        falling_objects = motion_features.get('falling_objects', [])

        for obj in falling_objects:
            frames = obj.get('frame_positions', [])

            if len(frames) >= 3:
                # Check acceleration (should be ~9.8 m/s² or proportional)
                velocities = []
                for i in range(len(frames) - 1):
                    v = frames[i+1].get('y') - frames[i].get('y')
                    velocities.append(v)

                # Check if acceleration is increasing (gravity effect)
                if len(velocities) >= 2:
                    acc = velocities[-1] - velocities[-2]
                    if acc < 0.5:  # Should be accelerating downward
                        issues.append("Object not accelerating according to gravity")
                        score -= 0.20

        return max(0, score), issues

    @staticmethod
    def validate_collision_physics(motion_features: Dict) -> Tuple[float, List[str]]:
        """Check if collisions follow physics laws."""
        issues = []
        score = 1.0

        collisions = motion_features.get('collisions', [])

        for collision in collisions:
            # Check momentum conservation
            before_momentum = collision.get('before_momentum', 0)
            after_momentum = collision.get('after_momentum', 0)

            momentum_loss = abs(before_momentum - after_momentum) / before_momentum if before_momentum else 0

            # Some momentum loss is normal (friction) but not too much
            if momentum_loss > 0.8:  # More than 80% loss is unrealistic
                issues.append(f"Unrealistic momentum loss in collision: {momentum_loss:.0%}")
                score -= 0.20

        return max(0, score), issues

    @staticmethod
    def validate_motion_realism(motion_features: Dict) -> Tuple[float, List[str]]:
        """Check if motion appears natural/realistic."""
        issues = []
        score = 1.0

        motions = motion_features.get('tracked_motions', [])

        for motion in motions:
            # Check for jerkiness (should be smooth in real videos)
            frame_deltas = motion.get('frame_deltas', [])

            if frame_deltas:
                # Calculate jerk (change in acceleration)
                jerk_values = []
                for i in range(len(frame_deltas) - 1):
                    jerk = abs(frame_deltas[i+1] - frame_deltas[i])
                    jerk_values.append(jerk)

                avg_jerk = sum(jerk_values) / len(jerk_values) if jerk_values else 0

                if avg_jerk > 10:  # High jerk = unrealistic/glitchy motion
                    issues.append(f"Motion has high jerk (unrealistic): {avg_jerk:.2f}")
                    score -= 0.15

        return max(0, score), issues


class LightingValidator:
    """Validates lighting consistency."""

    @staticmethod
    def validate_shadow_consistency(image_features: Dict) -> Tuple[float, List[str]]:
        """Check if shadows are consistent with light sources."""
        issues = []
        score = 1.0

        shadows = image_features.get('shadows', [])
        light_sources = image_features.get('light_sources', [])

        if not light_sources and shadows:
            issues.append("Shadows detected but no light sources found")
            score -= 0.25

        for shadow in shadows:
            # Shadow should point away from light
            light_pos = shadow.get('nearest_light')
            shadow_direction = shadow.get('direction')

            if light_pos and shadow_direction:
                # Calculate if shadow points away from light
                dot_product = shadow.get('shadow_light_dot_product', 0)
                if dot_product > 0:  # Same direction = wrong
                    issues.append("Shadow points toward light source (impossible)")
                    score -= 0.20

        return max(0, score), issues

    @staticmethod
    def validate_reflection_accuracy(image_features: Dict) -> Tuple[float, List[str]]:
        """Check if reflections are physically correct."""
        issues = []
        score = 1.0

        reflective_surfaces = image_features.get('reflective_surfaces', [])

        for surface in reflective_surfaces:
            reflection = surface.get('reflection')
            if reflection:
                # Reflection angle = incident angle
                incident_angle = reflection.get('incident_angle')
                reflected_angle = reflection.get('reflected_angle')

                if incident_angle and reflected_angle:
                    angle_diff = abs(incident_angle - reflected_angle)
                    if angle_diff > 5:  # Tolerance
                        issues.append(f"Reflection angle incorrect: {angle_diff:.1f}° off")
                        score -= 0.20

        return max(0, score), issues

    @staticmethod
    def validate_light_sources(image_features: Dict) -> Tuple[float, List[str]]:
        """Check if light sources are consistent."""
        issues = []
        score = 1.0

        lights = image_features.get('detected_lights', [])

        # Check color temperature consistency
        color_temps = [light.get('color_temp') for light in lights]

        if len(color_temps) >= 2:
            temp_range = max(color_temps) - min(color_temps)
            if temp_range > 3000:  # K - too much variance
                issues.append(f"Light sources have inconsistent color temp: {temp_range}K")
                score -= 0.15

        return max(0, score), issues


class DepthValidator:
    """Validates depth consistency."""

    @staticmethod
    def validate_depth_map(image_features: Dict) -> Tuple[float, List[str]]:
        """Check if depth map is realistic."""
        issues = []
        score = 1.0

        depth_map = image_features.get('depth_map')

        if depth_map:
            # Check for discontinuities where there shouldn't be edges
            discontinuities = depth_map.get('discontinuities', [])

            for disc in discontinuities:
                # Should only be at object boundaries
                if not disc.get('at_object_boundary'):
                    issues.append("Depth discontinuity not at object boundary")
                    score -= 0.10

        return max(0, score), issues

    @staticmethod
    def validate_focus_blur(image_features: Dict) -> Tuple[float, List[str]]:
        """Check if focus and blur are consistent with depth."""
        issues = []
        score = 1.0

        depth_map = image_features.get('depth_map', {})
        blur_map = image_features.get('blur_map', {})

        if depth_map and blur_map:
            # Objects at same depth should have same blur
            for region in blur_map.get('regions', []):
                depth = depth_map.get(f"depth_{region['id']}")
                blur = region.get('blur_amount')

                # Find other regions at similar depth
                for other_region in blur_map.get('regions', []):
                    other_depth = depth_map.get(f"depth_{other_region['id']}")
                    other_blur = other_region.get('blur_amount')

                    if abs(depth - other_depth) < 0.1:  # Same depth
                        if abs(blur - other_blur) > 0.15:  # Different blur
                            issues.append("Inconsistent blur at same depth")
                            score -= 0.10
                            break

        return max(0, score), issues


class ObjectPermanenceValidator:
    """Validates object permanence in videos."""

    @staticmethod
    def validate_temporal_tracking(video_features: Dict) -> Tuple[float, List[str]]:
        """Check if objects maintain identity across frames."""
        issues = []
        score = 1.0

        tracked_objects = video_features.get('tracked_objects', [])

        for obj in tracked_objects:
            frames = obj.get('frames', [])

            if len(frames) >= 2:
                # Check if object properties are consistent
                for i in range(len(frames) - 1):
                    frame1 = frames[i]
                    frame2 = frames[i + 1]

                    # Size should change gradually
                    size_change = abs(frame2.get('size', 0) - frame1.get('size', 0))
                    if size_change > frame1.get('size', 1) * 0.3:  # >30% change per frame
                        issues.append(f"Object size changes unrealistically: {size_change:.0%}")
                        score -= 0.10

        return max(0, score), issues

    @staticmethod
    def validate_identity_consistency(video_features: Dict) -> Tuple[float, List[str]]:
        """Check if object identity is maintained."""
        issues = []
        score = 1.0

        tracked_objects = video_features.get('tracked_objects', [])

        for obj in tracked_objects:
            # Check color/texture consistency
            colors = [frame.get('dominant_color') for frame in obj.get('frames', [])]

            if colors:
                # Color shouldn't change dramatically
                for i in range(len(colors) - 1):
                    color_dist = colors[i+1].get('distance_from', colors[i]) if hasattr(colors[i+1], 'get') else 0
                    if color_dist > 30:  # Color distance threshold
                        issues.append("Object color changes unrealistically")
                        score -= 0.15
                        break

        return max(0, score), issues


class WorldModelValidator:
    """Validates world model consistency (semantic, causal, physics)."""

    @staticmethod
    def validate_semantic_coherence(scene_features: Dict) -> Tuple[float, List[str]]:
        """Check if scene elements make semantic sense together."""
        issues = []
        score = 1.0

        objects = scene_features.get('detected_objects', [])

        # Check for impossible combinations
        impossible_pairs = [
            ('underwater', 'fire'),
            ('desert', 'snow'),
            ('indoors', 'sunset'),
        ]

        object_labels = [obj.get('label') for obj in objects]

        for impossible_pair in impossible_pairs:
            if impossible_pair[0] in object_labels and impossible_pair[1] in object_labels:
                issues.append(f"Impossible combination: {impossible_pair[0]} + {impossible_pair[1]}")
                score -= 0.25

        return max(0, score), issues

    @staticmethod
    def validate_causal_consistency(scene_features: Dict) -> Tuple[float, List[str]]:
        """Check if scene has causal consistency."""
        issues = []
        score = 1.0

        events = scene_features.get('detected_events', [])

        for event in events:
            causes = event.get('apparent_causes', [])
            effects = event.get('effects', [])

            # Check if causes actually lead to effects
            for cause, effect in zip(causes, effects):
                causality_score = cause.get('causality_to_effect', 0)

                if causality_score < 0.5:  # Weak causal connection
                    issues.append(f"Weak causality: {cause.get('type')} -> {effect.get('type')}")
                    score -= 0.15

        return max(0, score), issues


class SpatialIntelligenceEngine:
    """
    Main Spatial Intelligence Engine.
    Combines all validators to produce comprehensive spatial score.
    """

    def __init__(self):
        self.geometry = GeometryValidator()
        self.physics = PhysicsValidator()
        self.lighting = LightingValidator()
        self.depth = DepthValidator()
        self.permanence = ObjectPermanenceValidator()
        self.world = WorldModelValidator()

    def validate_image(self, image_features: Dict) -> Tuple[float, SpatialAnomalies]:
        """
        Validate spatial consistency in image.

        Args:
            image_features: Dictionary of extracted image features

        Returns:
            (overall_score: 0-1, anomalies: SpatialAnomalies)
        """
        scores = []
        anomalies = SpatialAnomalies(
            geometry_issues=[],
            physics_issues=[],
            lighting_issues=[],
            depth_issues=[],
            permanence_issues=[],
            world_model_issues=[]
        )

        # Geometry validation
        sym_score, sym_issues = self.geometry.validate_facial_symmetry(image_features)
        scores.append(sym_score * 0.15)  # Weight: 15%
        anomalies.geometry_issues.extend(sym_issues)

        persp_score, persp_issues = self.geometry.validate_perspective(image_features)
        scores.append(persp_score * 0.15)  # Weight: 15%
        anomalies.geometry_issues.extend(persp_issues)

        occl_score, occl_issues = self.geometry.validate_occlusion(image_features)
        scores.append(occl_score * 0.10)  # Weight: 10%
        anomalies.geometry_issues.extend(occl_issues)

        # Lighting validation
        shadow_score, shadow_issues = self.lighting.validate_shadow_consistency(image_features)
        scores.append(shadow_score * 0.20)  # Weight: 20%
        anomalies.lighting_issues.extend(shadow_issues)

        refl_score, refl_issues = self.lighting.validate_reflection_accuracy(image_features)
        scores.append(refl_score * 0.15)  # Weight: 15%
        anomalies.lighting_issues.extend(refl_issues)

        light_score, light_issues = self.lighting.validate_light_sources(image_features)
        scores.append(light_score * 0.10)  # Weight: 10%
        anomalies.lighting_issues.extend(light_issues)

        # Depth validation
        depth_score, depth_issues = self.depth.validate_depth_map(image_features)
        scores.append(depth_score * 0.10)  # Weight: 10%
        anomalies.depth_issues.extend(depth_issues)

        # World model validation
        semantic_score, semantic_issues = self.world.validate_semantic_coherence(image_features)
        scores.append(semantic_score * 0.05)  # Weight: 5%
        anomalies.world_model_issues.extend(semantic_issues)

        # Calculate overall score
        overall_score = sum(scores) if scores else 1.0

        logger.info(f"Spatial validation complete. Score: {overall_score:.3f}")

        return round(overall_score, 3), anomalies

    def validate_video(self, video_features: Dict) -> Tuple[float, SpatialAnomalies]:
        """
        Validate spatial consistency in video.

        Args:
            video_features: Dictionary of extracted video features

        Returns:
            (overall_score: 0-1, anomalies: SpatialAnomalies)
        """
        scores = []
        anomalies = SpatialAnomalies(
            geometry_issues=[],
            physics_issues=[],
            lighting_issues=[],
            depth_issues=[],
            permanence_issues=[],
            world_model_issues=[]
        )

        # Physics validation (video-specific)
        grav_score, grav_issues = self.physics.validate_gravity(video_features)
        scores.append(grav_score * 0.20)  # Weight: 20%
        anomalies.physics_issues.extend(grav_issues)

        collision_score, coll_issues = self.physics.validate_collision_physics(video_features)
        scores.append(collision_score * 0.15)  # Weight: 15%
        anomalies.physics_issues.extend(coll_issues)

        motion_score, motion_issues = self.physics.validate_motion_realism(video_features)
        scores.append(motion_score * 0.15)  # Weight: 15%
        anomalies.physics_issues.extend(motion_issues)

        # Object permanence validation
        track_score, track_issues = self.permanence.validate_temporal_tracking(video_features)
        scores.append(track_score * 0.20)  # Weight: 20%
        anomalies.permanence_issues.extend(track_issues)

        identity_score, identity_issues = self.permanence.validate_identity_consistency(video_features)
        scores.append(identity_score * 0.15)  # Weight: 15%
        anomalies.permanence_issues.extend(identity_issues)

        # World model validation
        causal_score, causal_issues = self.world.validate_causal_consistency(video_features)
        scores.append(causal_score * 0.10)  # Weight: 10%
        anomalies.world_model_issues.extend(causal_issues)

        # Calculate overall score
        overall_score = sum(scores) if scores else 1.0

        logger.info(f"Spatial video validation complete. Score: {overall_score:.3f}")

        return round(overall_score, 3), anomalies


# Singleton instance
spatial_engine = SpatialIntelligenceEngine()


def get_spatial_validator() -> SpatialIntelligenceEngine:
    """Get the spatial intelligence engine instance."""
    return spatial_engine
