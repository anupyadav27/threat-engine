# Noncompliant: Incorrect Einops pattern
pattern1 = [batch_size, num_channels, height, width]

# Compliant: Correct Einops pattern
pattern2 = [num_samples, num_channels, height, width]
