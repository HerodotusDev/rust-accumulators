#[cfg(test)]
mod tests {
    use std::vec;

    use mmr::helpers::{
        element_index_to_leaf_index, elements_count_to_leaf_count, find_peaks, find_siblings,
        get_peak_info,
    };

    #[test]
    fn test_find_peaks() {
        let correct: Vec<(usize, Vec<usize>)> = vec![
            (0, vec![]),
            (2, vec![]),
            (5, vec![]),
            (6, vec![]),
            (9, vec![]),
            (12, vec![]),
            (13, vec![]),
            (14, vec![]),
            (1, vec![1]),
            (3, vec![3]),
            (4, vec![3, 4]),
            (7, vec![7]),
            (8, vec![7, 8]),
            (10, vec![7, 10]),
            (11, vec![7, 10, 11]),
            (15, vec![15]),
        ];
        for (input, output) in correct.iter() {
            assert_eq!(find_peaks(*input), *output);
        }
    }

    #[test]
    fn test_elements_count_to_leaf_count() {
        let leaf_count = vec![
            Some(0),
            Some(1),
            None,
            Some(2),
            Some(3),
            None,
            None,
            Some(4),
            Some(5),
            None,
            Some(6),
            Some(7),
            None,
            None,
            None,
            Some(8),
        ];
        for (i, &expected) in leaf_count.iter().enumerate() {
            match expected {
                Some(val) => assert_eq!(elements_count_to_leaf_count(i).unwrap(), val),
                None => assert!(elements_count_to_leaf_count(i).is_err()),
            }
        }
    }

    #[test]
    fn test_element_index_to_leaf_index() {
        // const leafIndex = [null, 0, 1, null, 2, 3, null, null, 4, 5, null, 6, 7, null, null, null];
        let leaf_index = vec![
            None,
            Some(0),
            Some(1),
            None,
            Some(2),
            Some(3),
            None,
            None,
            Some(4),
            Some(5),
            None,
            Some(6),
            Some(7),
            None,
            None,
            None,
        ];
        for (i, &expected) in leaf_index.iter().enumerate() {
            match expected {
                Some(val) => assert_eq!(element_index_to_leaf_index(i).unwrap(), val),
                None => assert!(element_index_to_leaf_index(i).is_err()),
            }
        }
    }

    #[test]
    fn test_find_siblings() {
        let tests = [
            ("1:1", vec![]),
            ("3:1", vec![2]),
            ("3:2", vec![1]),
            ("4:1", vec![2]),
            ("4:2", vec![1]),
            ("4:4", vec![]),
            ("7:1", vec![2, 6]),
            ("7:2", vec![1, 6]),
            ("7:4", vec![5, 3]),
            ("7:5", vec![4, 3]),
            ("15:1", vec![2, 6, 14]),
            ("15:2", vec![1, 6, 14]),
            ("15:4", vec![5, 3, 14]),
            ("15:5", vec![4, 3, 14]),
            ("15:8", vec![9, 13, 7]),
            ("15:9", vec![8, 13, 7]),
            ("15:11", vec![12, 10, 7]),
            ("15:12", vec![11, 10, 7]),
            ("49:33", vec![32, 37, 45]),
        ];
        for (test, expected) in tests.iter() {
            let parts: Vec<_> = test.split(':').collect();
            let mmr_size: usize = parts[0].parse().unwrap();
            let element_index: usize = parts[1].parse().unwrap();
            assert_eq!(find_siblings(element_index, mmr_size).unwrap(), *expected);
        }
    }

    #[test]
    fn test_get_peak_info() {
        let peak_indices: Vec<Option<Vec<usize>>> = vec![
            Some(vec![0]), // peaks: [1]
            None,
            Some(vec![0, 0, 0]),    // peaks: [3]
            Some(vec![0, 0, 0, 1]), // peaks: [3, 4]
            None,
            None,
            Some(vec![0, 0, 0, 0, 0, 0, 0]),    // peaks: [7]
            Some(vec![0, 0, 0, 0, 0, 0, 0, 1]), // peaks: [7, 8]
            None,
            Some(vec![0, 0, 0, 0, 0, 0, 0, 1, 1, 1]), // peaks: [7, 10]
            Some(vec![0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 2]), // peaks: [7, 10, 11]
            None,
            None,
            None,
            Some(vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]), // peaks: [15]
            Some(vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]), // peaks: [15, 16]
            None,
            Some(vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1]), // peaks: [15, 18]
            Some(vec![
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 2,
            ]), // peaks: [15, 18, 19]
            None,
            None,
            Some(vec![
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1,
            ]), // peaks: [15, 22]
            Some(vec![
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 2,
            ]), // peaks: [15, 22, 23]
            None,
            Some(vec![
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 2, 2, 2,
            ]), // peaks: [15, 22, 25]
            Some(vec![
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 2, 2, 2, 3,
            ]), // peaks: [15, 22, 25, 26]
            None,
            None,
            None,
            None,
            Some(vec![
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0,
            ]), // peaks: [31]
        ];

        let peak_heights: Vec<Option<Vec<usize>>> = vec![
            Some(vec![0]), // peaks: [1]
            None,
            Some(vec![1, 1, 1]),    // peaks: [3]
            Some(vec![1, 1, 1, 0]), // peaks: [3, 4]
            None,
            None,
            Some(vec![2, 2, 2, 2, 2, 2, 2]),    // peaks: [7]
            Some(vec![2, 2, 2, 2, 2, 2, 2, 0]), // peaks: [7, 8]
            None,
            Some(vec![2, 2, 2, 2, 2, 2, 2, 1, 1, 1]), // peaks: [7, 12]
            Some(vec![2, 2, 2, 2, 2, 2, 2, 1, 1, 1, 0]), // peaks: [7, 12, 11]
            None,
            None,
            None,
            Some(vec![3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3]), // peaks: [15]
            Some(vec![3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 0]), // peaks: [15, 16]
            None,
            Some(vec![3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 1, 1, 1]), // peaks: [15, 18]
            Some(vec![
                3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 1, 1, 1, 0,
            ]), // peaks: [15, 18, 19]
            None,
            None,
            Some(vec![
                3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 2, 2, 2, 2, 2, 2, 2,
            ]), // peaks: [15, 22]
            Some(vec![
                3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 2, 2, 2, 2, 2, 2, 2, 0,
            ]), // peaks: [15, 22, 23]
            None,
            Some(vec![
                3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 2, 2, 2, 2, 2, 2, 2, 1, 1, 1,
            ]), // peaks: [15, 22, 25]
            Some(vec![
                3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 2, 2, 2, 2, 2, 2, 2, 1, 1, 1, 0,
            ]), // peaks: [15, 22, 25, 26]
            None,
            None,
            None,
            None,
            Some(vec![
                4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4,
                4,
            ]), // peaks: [29]
        ];

        for elements_count in 1..=peak_indices.len() {
            let output1 = &peak_indices[elements_count - 1];
            let output2 = &peak_heights[elements_count - 1];

            if let (Some(output1_vec), Some(output2_vec)) = (output1, output2) {
                if !output1_vec.is_empty() && !output2_vec.is_empty() {
                    for element_index in 1..=output1_vec.len() {
                        let expected = (
                            output1_vec[element_index - 1],
                            output2_vec[element_index - 1],
                        );
                        assert_eq!(get_peak_info(elements_count, element_index), expected);
                    }
                }
            }
        }
    }
}
