#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "list.h"

#define MAX_STR_LEN 100

struct data {
	double arrival_time;
	double packet_size;
	unsigned int flow_number;
};

static int num_flows = 4;
static int *weights;
static unsigned long link_rate;
static void **flows;

void read_weights(FILE *fp)
{
	char str[MAX_STR_LEN];
	const char *tok="\n ";
	char *wt;
	int i=0;

	if (fgets(str, MAX_STR_LEN, fp) == NULL) {
		printf("Error reading weights\n");
		exit(1);
	}

	weights = malloc(num_flows * sizeof(*weights));

	for (wt = strtok(str,tok);
	     wt;
	     i++, wt = strtok(NULL,tok)) {
		weights[i] = atoi(wt);
		printf("weight:%d\n",weights[i]);
	}
}

void read_link_rate(FILE *fp)
{
	char str[MAX_STR_LEN];

	if (fgets(str,MAX_STR_LEN,fp) == NULL) {
		printf("Link rate read error\n");
		exit(1);
	}

	link_rate = atoi(str);
}

void init_flows()
{
	int i;

	flows = malloc(num_flows * sizeof(*flows));

	for (i=0; i<num_flows; i++) {
		flows[i] = list_create();
	}
}

void read_arrival_flows(FILE *fp)
{
	char str[MAX_STR_LEN];
	const char *tok="\n ";
	struct data *tmp;

	while (fgets(str,MAX_STR_LEN,fp)) {
		tmp = malloc(sizeof(*tmp));
		tmp->arrival_time = atof(strtok(str,tok));
		tmp->packet_size = atof(strtok(NULL,tok))*8;
		tmp->flow_number = atoi(strtok(NULL,tok));

		list_add_tail(flows[tmp->flow_number-1],tmp);
	}
}

int print(void *data)
{
	struct data *tmp = (struct data *)data;
	printf("%f->",tmp->arrival_time);
	return 1;
}

void trav_flows()
{
	int i;

	for (i=0; i<num_flows; i++) {
		printf("Flow %d:",i+1);
		list_trav(flows[i],print);
		printf("NULL\n");
	}
}

unsigned long check_backlog_flows(double curr_time)
{
	int i;
	struct data *tmp;
	unsigned long bitmap = 0;

	for (i=0; i<num_flows; i++) {
		if ((tmp = list_peek_head(flows[i])) &&
		    (tmp->arrival_time <= curr_time)) {
			bitmap |= (1<<i);
		}
	}
	return bitmap;
}

int flows_remaining()
{
	int i;

	for (i=0; i<num_flows; i++) {
		if (list_peek_head(flows[i]))
			return 1;
	}
	return 0;
}

unsigned int find_total_wt(unsigned long bitmap)
{
	int i;
	unsigned int wt = 0;

	for (i=0;i<num_flows;i++) {
		if (bitmap & (1<<i)) {
			wt += weights[i];
		}
	}
	return wt;
}

unsigned int find_next_flow(unsigned long bitmap,
			    unsigned int wt)
{
	double end_time = 65535;
	int next_flow = -1;
	int i;
	double end_flow;
	struct data *tmp;

	for (i=0;i<num_flows;i++) {
		if (bitmap & (1<<i)) {
			tmp = list_peek_head(flows[i]);
			end_flow = tmp->packet_size / (link_rate*(double)weights[i]/(double)wt);

			if (end_flow < end_time) {
				end_time = end_flow;
				next_flow = i;
			}
		}
	}
	return next_flow;
}

void calc_pgps()
{
	unsigned long bitmap = 0;
        double curr_time = 0;
	struct data *tmp;
	unsigned int total_wt;
	int flow;

	while(1) {
		bitmap = check_backlog_flows(curr_time);

		if (bitmap) {
			total_wt = find_total_wt(bitmap);
			flow = find_next_flow(bitmap,total_wt);
			tmp = list_del_head(flows[flow]);
			printf("%.3f %d\n",curr_time,flow+1);
			curr_time += (tmp->packet_size / link_rate);
		} else if (flows_remaining()) {
			curr_time += 1;
		} else {
			break;
		}
	}
}

int main(int argc, char **argv)
{
	FILE *fp;

	if (argc == 1) {
		printf("Usage:%s <filename> [flows]\n",argv[0]);
		exit(1);
	} else if (argc == 3) {
		num_flows = atoi(argv[2]);
	}

	printf("Number of flows: %d\n", num_flows);

	/* Open the input file */
	fp = fopen(argv[1],"r");
	if (fp == NULL) {
		printf("Error opening file\n");
		exit(1);
	}

	/* Read weights of flows */
	read_weights(fp);

	/* Read link rate */
	read_link_rate(fp);

	/* Initialize flow heads */
	init_flows();

	/* Read flow arrival data */
	read_arrival_flows(fp);

	/* Traverse the flows */
	trav_flows();

	/* Calculate departure times */
	calc_pgps();

	/* Close the input file */
	fclose(fp);

	return 0;
}
