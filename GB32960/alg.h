#pragma once
class CSort
{
public:
	CSort() = default;
	~CSort() = default;

public:
	static void Display(int arr[], int len);
	/*堆特点
	小堆节点N;arr[N] < arr[2N+1] && arr[N] < arr[2N+2]
	非叶子节点数：N/2,叶子节点数N+1/2
	创建最小堆需遍历前N / 2个非叶子节点( [ 0 ~ n/2-1 ] )进行下滤即可
	*/
	static void MinHeapSort(int arr[], int len);
	static void MaxHeapSort(int arr[], int len);

	/*
	dfs/bfs
	*/
	static void Dfs();
};

void CSort::Display(int arr[], int len)
{
	for (int i = 0; i < len; i++)
	{
		printf("%d ", arr[i]);
	}
	printf("\n");
}

void CSort::MinHeapSort(int arr[], int len)
{
	printf("before MinHeapSort:");
	Display(arr, len);
	auto adjustHeap = [](int arr[], int len, int index)
	{
		int child = 2 * index + 1; //左子节点
		for (; child < len; child = 2 * child + 1)
		{
			//如果右子节点存在，且别左节点小则交换位置
			if (child + 1 < len && arr[child] < arr[child + 1])
			{
				child++;
			}
			//判断子节点和父节点大小
			if (arr[index] < arr[child])
			{
				swap(arr[index], arr[child]);
				index = child;
			}
			else
			{
				break;
			}
		}
	};
	//非叶子节点从底层开始向上到顶层0，使堆顶元素最大
	for (int i = len / 2 - 1; i >= 0; i--)
	{
		adjustHeap(arr, len, i);
	}
	//将堆顶元素与末尾元素进行交换，使末尾元素最大，然后继续调整堆
	for (int i = len - 1; i > 0; i--)
	{
		swap(arr[0], arr[i]);
		adjustHeap(arr, i, 0);
	}
	printf("after MinHeapSort:");
	Display(arr, len);
}

void CSort::MaxHeapSort(int arr[], int len)
{
	printf("before MaxHeapSort:");
	Display(arr, len);
	auto adjustheap = [](int arr[], int len, int index)
	{
		int child = 2 * index + 1;
		for (; child < len; child = 2 * child + 1)
		{
			if (child + 1 < len && arr[child] > arr[child + 1])
			{
				child++;
			}
			if (arr[index] > arr[child])
			{
				swap(arr[index], arr[child]);
				index = child;
			}
			else
			{
				break;
			}
		}
	};
	for (int i = len / 2 - 1; i >= 0; i--)
	{
		adjustheap(arr, len, i);
	}
	for (int i = len - 1; i > 0; i--)
	{
		swap(arr[0], arr[i]);
		adjustheap(arr, i, 0);
	}
	printf("after MaxHeapSort:");
	Display(arr, len);
}

// using AdjacentMatrix = map<int, vector<int>>;
#define MAX 8
int matrix[MAX][MAX] = {
	{0, 1, 1, 0, 0, 0, 0, 0},
	{0, 0, 0, 1, 1, 0, 0, 0},
	{0, 0, 0, 0, 0, 1, 1, 0},
	{0, 1, 0, 0, 0, 0, 0, 1},
	{0, 1, 0, 0, 0, 0, 0, 1},
	{0, 0, 1, 0, 0, 0, 0, 1},
	{0, 0, 1, 0, 0, 0, 0, 1},
	{0, 0, 0, 1, 1, 1, 1, 0},
};

void Depth()
{
	bool bVisit[MAX] = {false};
	stack<int> s;
	s.push(0);
	bVisit[0] = true;
	printf("Depth: %d ", s.top());
	while (!s.empty())
	{
		int id = s.top();
		int i = 0;
		for (; i < MAX; i++)
		{
			if (matrix[id][i] == 1 && bVisit[i] == false)
			{
				s.push(i);
				bVisit[i] = true;
				printf("%d ", i);
				break;
			}
		}
		if (i == MAX)
		{
			s.pop();
		}
	}
}

void Breadth()
{
	bool bVisit[MAX] = {false};
	queue<int> q;
	q.push(0);
	bVisit[0] = true;
	printf("Breadth: %d ", q.front());
	while (!q.empty())
	{
		int id = q.front();
		q.pop();
		for (int i = 0; i < MAX; i++)
		{
			if (matrix[id][i] == 1 && bVisit[i] == false)
			{
				q.push(i);
				bVisit[i] = true;
				printf("%d ", i);
			}
		}
	}
}

// dp 三角问题
int triangle[4][4] = {
	{2, 0, 0, 0},
	{3, 4, 0, 0},
	{6, 5, 7, 0},
	{4, 1, 8, 3},
};
// dp状态转换方程

void test_alg()
{
	////travers
	Depth();
	Breadth();
	////sort
	int arr[] = {4, 6, 8, 5, 9, 4, 5, 8};
	CSort::MinHeapSort(arr, 8);
	CSort::MaxHeapSort(arr, 8);
}