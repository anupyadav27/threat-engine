import numpy as np

# This should trigger the rule: np.array with forbidden built-in dtype alias
arr1 = np.array([1, 2, 3], dtype='int')
arr2 = np.array([1.0, 2.0, 3.0], dtype='float')
arr3 = np.array(['a', 'b', 'c'], dtype='str')
arr4 = np.array([True, False], dtype='bool')
arr5 = np.array([1+2j, 3+4j], dtype='complex')

# This should NOT trigger the rule (compliant examples)
arr6 = np.array([1, 2, 3], dtype=np.int32)
arr7 = [1, 2, 3]
