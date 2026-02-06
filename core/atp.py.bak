import numpy as np

class AdversarialTrainingPipeline:
    """
    New Code #1: Generates synthetic adversarial examples.
    """
    def __init__(self):
        self.training_set = []

    def generate_attack(self, base_vector, rotation_angle):
        noise = np.random.normal(0, 0.1, base_vector.shape)
        attack_vector = base_vector + (noise * rotation_angle)
        return attack_vector

    def self_train(self, base_vector, rotation_angle):
        adv = self.generate_attack(base_vector, rotation_angle)
        self.training_set.append(adv)
        return len(self.training_set)
