#include<stdio.h>
#include<unistd.h>
void bubble_sort(int a[], int n)
{
	int i = 0,j = 0,tmp;
	for(i = 0; i <=n; i++)
	{
		for(j = 0;j <n-i-1;j++)
		{
			if(a[j]>a[j+1])
			{
				tmp = a[j];
				a[j] = a[j+1];
				a[j+1] = tmp;
			}
		}
		
	}
}
int main()
{
	int arr[10] = {10,9,8,7,6,1,2,3,5,4};
	bubble_sort(arr,sizeof(arr));
	for(int i = 0; i <= sizeof(arr);i++)
	{
		printf("%d ",arr[i]);
	}
	printf("\n");
	return 0;
}
