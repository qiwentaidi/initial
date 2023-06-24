package common

// 去除某个元素
func RemoveElement(arr []string, ele string) (newArr []string) {
	for _, v := range arr {
		if v != ele {
			newArr = append(newArr, v)
		}
	}
	return newArr
}

// 字符串数组去重
func RemoveDuplicates[T comparable](arr []T) []T {
	encountered := map[T]bool{}
	result := []T{}
	for _, v := range arr {
		if !encountered[v] {
			// Record this element as an encountered element.
			encountered[v] = true
			// Append to result slice.
			result = append(result, v)
		}
	}
	// Return the new slice.
	return result
}

// 替换指定元素
func ReplaceElement(slice []string, old, new string) []string {
	newSlice := []string{}
	for _, v := range slice {
		if v != old {
			newSlice = append(newSlice, v)
		} else {
			newSlice = append(newSlice, new)
		}
	}
	return newSlice
}
