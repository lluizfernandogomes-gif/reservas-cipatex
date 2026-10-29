-- Destino / motivo obrigatório na reserva
begin;
create or replace function reservas.criar_reserva(p_veiculo uuid, p_inicio timestamptz, p_fim timestamptz,
  p_destino text default null, p_usuario uuid default null) returns reservas.reservas
language plpgsql security definer set search_path = reservas, public, extensions as $$
declare me reservas.usuarios := reservas.eu(); cfg jsonb; v reservas.veiculos; alvo uuid; r reservas.reservas; b reservas.bloqueios; v_cnh date;
begin
  if me.id is null then raise exception 'Acesso negado'; end if;
  if me.papel = 'portaria' then raise exception 'A portaria não faz reservas'; end if;
  select config into cfg from reservas.empresas where id = me.empresa_id;
  select * into v from reservas.veiculos where id = p_veiculo and empresa_id = me.empresa_id;
  if v.id is null or not v.ativo or v.excluido then raise exception 'Veículo indisponível'; end if;
  alvo := coalesce(p_usuario, me.id);
  if alvo <> me.id then
    if me.papel <> 'gestor' then raise exception 'Só gestor pode reservar para outra pessoa'; end if;
    perform 1 from reservas.usuarios where id = alvo and empresa_id = me.empresa_id and ativo and papel <> 'portaria';
    if not found then raise exception 'Usuário inválido'; end if;
  end if;
  if p_inicio is null or p_fim is null or p_fim <= p_inicio then raise exception 'O fim precisa ser depois do início'; end if;
  if p_inicio < now() - interval '10 minutes' then raise exception 'Não dá para reservar no passado'; end if;
  if length(trim(coalesce(p_destino, ''))) < 3 then raise exception 'Informe o destino / motivo da viagem'; end if;
  select cnh_validade into v_cnh from reservas.condutores where usuario_id = alvo;
  if v_cnh is not null and v_cnh < (p_fim at time zone 'America/Sao_Paulo')::date then
    raise exception 'CNH vencida (ou vence antes do fim da reserva): validade %. Atualize a CNH com o gestor.', to_char(v_cnh, 'DD/MM/YYYY'); end if;
  if me.papel <> 'gestor' then
    if p_fim - p_inicio > make_interval(hours => (cfg->>'max_horas')::int) then
      raise exception 'A reserva pode ter no máximo % dias', trim_scale(round((cfg->>'max_horas')::numeric / 24, 1)); end if;
    if p_inicio > now() + make_interval(days => (cfg->>'antecedencia_dias')::int) then
      raise exception 'Só dá para reservar com até % dias de antecedência', cfg->>'antecedencia_dias'; end if;
  end if;
  select * into b from reservas.bloqueios x where x.veiculo_id = v.id and x.ativo and x.periodo && tstzrange(p_inicio, p_fim, '[)') limit 1;
  if b.id is not null then
    raise exception 'Veículo bloqueado nesse período (%): %', to_char(b.inicio at time zone 'America/Sao_Paulo','DD/MM HH24:MI') || ' a ' || to_char(b.fim at time zone 'America/Sao_Paulo','DD/MM HH24:MI'), b.motivo; end if;
  if exists (select 1 from reservas.reservas x where x.usuario_id = alvo and x.status in ('reservada','em_uso')
             and x.periodo && tstzrange(p_inicio, p_fim, '[)')) then
    raise exception 'Já existe uma reserva desse usuário nesse horário'; end if;
  begin
    insert into reservas.reservas(empresa_id, veiculo_id, usuario_id, inicio, fim, destino, criado_por)
    values (me.empresa_id, v.id, alvo, p_inicio, p_fim, nullif(trim(p_destino), ''), me.id)
    returning * into r;
  exception when exclusion_violation then
    raise exception 'Esse veículo já está reservado nesse horário';
  end;
  return r;
end $$;
commit;
