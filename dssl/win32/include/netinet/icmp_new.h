
struct icmp 
{
     u_char     icmp_type;
     u_char     icmp_code;
     u_short    icmp_cksum;
     u_short    id;
     u_short    seqno;
} ;

                                  