-- ============================================================
-- Login por e-mail, cadastro completo do condutor, exclusão de veículo
-- ============================================================

-- 1) Login pode ser e-mail (ou o formato antigo, ex.: "admin")
alter table reservas.usuarios drop constraint usuarios_usuario_check;
alter table reservas.usuarios add constraint usuarios_usuario_check check (
  usuario ~ '^[a-z0-9._-]{3,40}$' or (usuario ~ '^[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}$' and length(usuario) <= 120));

create or replace function reservas.login_valido(p text) returns boolean
language sql immutable set search_path = '' as $$
  select p ~ '^[a-z0-9._-]{3,40}$' or (p ~ '^[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}$' and length(p) <= 120)
$$;

-- e-mail do Auth: se o login já é e-mail, usa ele mesmo
create or replace function reservas.email_login(p_slug text, p_usuario text) returns text
language sql immutable set search_path = '' as $$
  select case when position('@' in p_usuario) > 0 then lower(trim(p_usuario))
              else lower(p_usuario) || '.' || lower(p_slug) || '@reservas.powertec.app' end
$$;

-- 2) Dados pessoais do condutor (só gestor lê; LGPD)
create table reservas.condutores(
  usuario_id uuid primary key references reservas.usuarios on delete cascade,
  empresa_id uuid not null references reservas.empresas on delete cascade,
  cargo text, setor text,
  data_nascimento date,
  cpf text check (cpf is null or cpf ~ '^[0-9]{11}$'),
  rg text, rg_orgao text,
  telefone text, email_contato text,
  cep text, logradouro text, numero text, complemento text, bairro text, cidade text, uf text check (uf is null or uf ~ '^[A-Z]{2}$'),
  cnh_numero text, cnh_categoria text, cnh_expedicao date, cnh_validade date, cnh_primeira_habilitacao date,
  observacoes text,
  atualizado_em timestamptz not null default now(),
  atualizado_por uuid references reservas.usuarios
);
create unique index condutores_cpf_empresa on reservas.condutores (empresa_id, cpf) where cpf is not null;
alter table reservas.condutores enable row level security;
create policy condutores_gestor on reservas.condutores for select to authenticated
  using (empresa_id = (select reservas.minha_empresa()) and (select reservas.sou_gestor()));
grant select on reservas.condutores to authenticated;
grant all on reservas.condutores to service_role;

create function reservas.salvar_condutor(p_usuario uuid, p jsonb) returns void
language plpgsql security definer set search_path = reservas, public as $$
declare me reservas.usuarios := reservas.eu(); v_cpf text := nullif(regexp_replace(coalesce(p->>'cpf',''), '[^0-9]', '', 'g'), '');
begin
  if me.id is null or me.papel <> 'gestor' then raise exception 'Só gestor'; end if;
  perform 1 from reservas.usuarios where id = p_usuario and empresa_id = me.empresa_id;
  if not found then raise exception 'Usuário não encontrado'; end if;
  if v_cpf is not null and length(v_cpf) <> 11 then raise exception 'CPF deve ter 11 dígitos'; end if;
  begin
    insert into reservas.condutores as c (usuario_id, empresa_id, cargo, setor, data_nascimento, cpf, rg, rg_orgao, telefone, email_contato,
      cep, logradouro, numero, complemento, bairro, cidade, uf, cnh_numero, cnh_categoria, cnh_expedicao, cnh_validade, cnh_primeira_habilitacao,
      observacoes, atualizado_em, atualizado_por)
    values (p_usuario, me.empresa_id, nullif(trim(p->>'cargo'),''), nullif(trim(p->>'setor'),''), nullif(p->>'data_nascimento','')::date, v_cpf,
      nullif(trim(p->>'rg'),''), nullif(upper(trim(p->>'rg_orgao')),''), nullif(trim(p->>'telefone'),''), nullif(lower(trim(p->>'email_contato')),''),
      nullif(regexp_replace(coalesce(p->>'cep',''),'[^0-9]','','g'),''), nullif(trim(p->>'logradouro'),''), nullif(trim(p->>'numero'),''),
      nullif(trim(p->>'complemento'),''), nullif(trim(p->>'bairro'),''), nullif(trim(p->>'cidade'),''), nullif(upper(trim(p->>'uf')),''),
      nullif(trim(p->>'cnh_numero'),''), nullif(upper(trim(p->>'cnh_categoria')),''), nullif(p->>'cnh_expedicao','')::date,
      nullif(p->>'cnh_validade','')::date, nullif(p->>'cnh_primeira_habilitacao','')::date, nullif(trim(p->>'observacoes'),''), now(), me.id)
    on conflict (usuario_id) do update set
      cargo = excluded.cargo, setor = excluded.setor, data_nascimento = excluded.data_nascimento, cpf = excluded.cpf, rg = excluded.rg,
      rg_orgao = excluded.rg_orgao, telefone = excluded.telefone, email_contato = excluded.email_contato, cep = excluded.cep,
      logradouro = excluded.logradouro, numero = excluded.numero, complemento = excluded.complemento, bairro = excluded.bairro,
      cidade = excluded.cidade, uf = excluded.uf, cnh_numero = excluded.cnh_numero, cnh_categoria = excluded.cnh_categoria,
      cnh_expedicao = excluded.cnh_expedicao, cnh_validade = excluded.cnh_validade, cnh_primeira_habilitacao = excluded.cnh_primeira_habilitacao,
      observacoes = excluded.observacoes, atualizado_em = now(), atualizado_por = me.id;
  exception when unique_violation then raise exception 'Já existe outro condutor com esse CPF';
  end;
end $$;

-- 3) Regras de login atualizadas nas funções de usuário
create or replace function reservas.salvar_usuario(p_id uuid, p_nome text, p_usuario text, p_papel text, p_ativo boolean)
returns jsonb language plpgsql security definer set search_path = reservas, public, extensions as $$
declare me reservas.usuarios := reservas.eu(); u reservas.usuarios; v_login text := lower(trim(p_usuario)); c text;
begin
  if me.id is null or me.papel <> 'gestor' then raise exception 'Só gestor pode gerenciar usuários'; end if;
  if p_papel not in ('usuario','gestor','portaria') then raise exception 'Papel inválido'; end if;
  if not reservas.login_valido(v_login) then raise exception 'Login inválido: use o e-mail da pessoa (ex.: joao.silva@cipatex.com.br)'; end if;
  if length(trim(coalesce(p_nome,''))) < 2 then raise exception 'Informe o nome'; end if;
  if p_id is null then
    begin
      insert into reservas.usuarios(empresa_id, nome, usuario, papel, ativo)
      values (me.empresa_id, trim(p_nome), v_login, p_papel, coalesce(p_ativo, true)) returning * into u;
    exception when unique_violation then raise exception 'Já existe o usuário "%"', v_login; end;
    c := reservas._novo_codigo(u.id);
    return jsonb_build_object('id', u.id, 'codigo', c);
  end if;
  select * into u from reservas.usuarios where id = p_id and empresa_id = me.empresa_id for update;
  if u.id is null then raise exception 'Usuário não encontrado'; end if;
  if u.id = me.id and (p_papel <> 'gestor' or p_ativo is distinct from true) then
    raise exception 'Você não pode remover seu próprio acesso de gestor'; end if;
  if v_login <> u.usuario and u.auth_id is not null then
    raise exception 'O login não pode ser alterado depois do primeiro acesso'; end if;
  begin
    update reservas.usuarios set nome = trim(p_nome), usuario = v_login, papel = p_papel, ativo = coalesce(p_ativo, ativo) where id = p_id;
  exception when unique_violation then raise exception 'Já existe o usuário "%"', v_login; end;
  return jsonb_build_object('id', p_id);
end $$;

create or replace function reservas.importar_usuarios(p_linhas jsonb) returns jsonb
language plpgsql security definer set search_path = reservas, public, extensions as $$
declare me reservas.usuarios := reservas.eu(); l jsonb; i int := 0; v_login text; v_papel text; v_nome text; u uuid;
  criados jsonb := '[]'; erros jsonb := '[]'; ignorados int := 0;
begin
  if me.id is null or me.papel <> 'gestor' then raise exception 'Só gestor'; end if;
  if jsonb_array_length(p_linhas) > 1000 then raise exception 'Máximo de 1000 linhas por importação'; end if;
  for l in select * from jsonb_array_elements(p_linhas) loop
    i := i + 1;
    begin
      v_nome := trim(coalesce(l->>'nome',''));
      v_login := lower(trim(coalesce(l->>'usuario','')));
      v_papel := lower(trim(coalesce(nullif(l->>'papel',''), 'usuario')));
      v_papel := case when v_papel in ('gestor') then 'gestor' when v_papel in ('portaria','porteiro') then 'portaria'
                      when v_papel in ('usuario','usuário','motorista') then 'usuario' else v_papel end;
      if length(v_nome) < 2 then raise exception 'nome vazio'; end if;
      if not reservas.login_valido(v_login) then raise exception 'login "%" inválido', v_login; end if;
      if v_papel not in ('usuario','gestor','portaria') then raise exception 'papel "%" inválido', v_papel; end if;
      if exists (select 1 from reservas.usuarios where empresa_id = me.empresa_id and usuario = v_login) then
        ignorados := ignorados + 1; continue;
      end if;
      insert into reservas.usuarios(empresa_id, nome, usuario, papel) values (me.empresa_id, v_nome, v_login, v_papel) returning id into u;
      if nullif(trim(coalesce(l->>'cargo','')),'') is not null or nullif(trim(coalesce(l->>'setor','')),'') is not null then
        insert into reservas.condutores(usuario_id, empresa_id, cargo, setor) values (u, me.empresa_id, nullif(trim(l->>'cargo'),''), nullif(trim(l->>'setor'),''));
      end if;
      criados := criados || jsonb_build_object('nome', v_nome, 'usuario', v_login, 'papel', v_papel, 'codigo', reservas._novo_codigo(u));
    exception when others then
      erros := erros || jsonb_build_object('linha', i + 1, 'erro', sqlerrm);
    end;
  end loop;
  return jsonb_build_object('criados', criados, 'ignorados', ignorados, 'erros', erros);
end $$;

-- 4) Exclusão de veículo: apaga de verdade se não tem histórico; senão arquiva
alter table reservas.veiculos add column excluido boolean not null default false;

create function reservas.excluir_veiculo(p_id uuid) returns text
language plpgsql security definer set search_path = reservas, public as $$
declare me reservas.usuarios := reservas.eu(); v reservas.veiculos; tem_hist boolean;
begin
  if me.id is null or me.papel <> 'gestor' then raise exception 'Só gestor'; end if;
  select * into v from reservas.veiculos where id = p_id and empresa_id = me.empresa_id for update;
  if v.id is null then raise exception 'Veículo não encontrado'; end if;
  if exists (select 1 from reservas.reservas where veiculo_id = v.id and status = 'em_uso') then
    raise exception 'O veículo está em uso. Registre a devolução antes de excluir.'; end if;
  update reservas.reservas set status = 'cancelada', cancelada_por = me.id, cancelada_em = now(), motivo_cancelamento = 'Veículo removido da frota'
   where veiculo_id = v.id and status = 'reservada';
  update reservas.bloqueios set ativo = false where veiculo_id = v.id and ativo;
  tem_hist := exists (select 1 from reservas.reservas where veiculo_id = v.id)
           or exists (select 1 from reservas.manut_ordens where veiculo_id = v.id);
  if tem_hist then
    update reservas.veiculos set excluido = true, ativo = false where id = v.id;
    return 'arquivado';
  end if;
  update reservas.veiculos set excluido = true, ativo = false, placa = placa || '#' || left(id::text, 8) where id = v.id;
  return 'excluido';
end $$;

-- 5) KM desconhecido (0) não trava a primeira retirada
create or replace function reservas.retirar(p_id uuid, p_km int) returns void
language plpgsql security definer set search_path = reservas, public as $$
declare me reservas.usuarios := reservas.eu(); r reservas.reservas; v reservas.veiculos; cfg jsonb;
begin
  if me.id is null then raise exception 'Acesso negado'; end if;
  if me.papel not in ('portaria','gestor') then raise exception 'A entrega da chave é registrada pela portaria'; end if;
  select * into r from reservas.reservas where id = p_id and empresa_id = me.empresa_id for update;
  if r.id is null then raise exception 'Reserva não encontrada'; end if;
  if r.status <> 'reservada' then raise exception 'Essa reserva não está disponível para retirada'; end if;
  select config into cfg from reservas.empresas where id = me.empresa_id;
  if now() < r.inicio - make_interval(mins => coalesce((cfg->>'retirada_antecipada_min')::int, 30)) then
    raise exception 'Ainda é cedo: a retirada abre % minutos antes do horário', coalesce(cfg->>'retirada_antecipada_min','30'); end if;
  if now() >= r.fim then raise exception 'O horário dessa reserva já acabou'; end if;
  select * into v from reservas.veiculos where id = r.veiculo_id for update;
  if exists (select 1 from reservas.reservas x where x.veiculo_id = v.id and x.status = 'em_uso' and x.id <> r.id) then
    raise exception 'O veículo ainda não foi devolvido pela reserva anterior'; end if;
  if p_km is null or p_km < v.km_atual then
    raise exception 'KM de saída não pode ser menor que o último registrado (% km)', v.km_atual; end if;
  if v.km_atual > 0 and p_km > v.km_atual + 5000 then raise exception 'KM muito acima do último registrado (% km). Confira o valor.', v.km_atual; end if;
  perform set_config('reservas.via_rpc', '1', true);
  update reservas.reservas set status = 'em_uso', km_saida = p_km, retirada_em = now(), retirada_por = me.id where id = p_id;
  update reservas.veiculos set km_atual = p_km where id = v.id;
  insert into reservas.km_leituras(empresa_id, veiculo_id, km, origem, reserva_id, usuario_id)
  values (me.empresa_id, v.id, p_km, 'retirada', p_id, me.id);
end $$;

-- 6) Preventiva: ignora leitura de KM zero (carro cadastrado sem KM) ao estimar a base
create or replace function reservas.manut_situacao() returns table(
  veiculo_id uuid, plano_id uuid, plano text, intervalo_km int, intervalo_meses int,
  ultimo_data date, ultimo_km int, estimado boolean, km_atual int,
  prox_km int, prox_data date, faltam_km int, faltam_dias int, situacao text)
language plpgsql stable security definer set search_path = reservas, public as $$
declare me reservas.usuarios := reservas.eu(); hoje date := (now() at time zone 'America/Sao_Paulo')::date;
begin
  if me.id is null or me.papel <> 'gestor' then raise exception 'Só gestor'; end if;
  return query
  with ap as (
    select v.id vid, v.km_atual vkm, v.criado_em vcri, p.id pid, p.nome pnome, p.intervalo_km pik, p.intervalo_meses pim,
           p.aviso_km pak, p.aviso_dias pad, p.criado_em pcri
      from reservas.veiculos v join reservas.manut_planos p on p.empresa_id = v.empresa_id
     where v.empresa_id = me.empresa_id and v.ativo and not v.excluido and p.ativo
       and (p.veiculo_id = v.id or (p.veiculo_id is null and (p.categoria_id is null or p.categoria_id = v.categoria_id)))
  ), base as (
    select ap.*, u.data_conclusao u_data, u.km u_km, greatest(ap.pcri, ap.vcri) b_ts
      from ap left join lateral (
        select o.data_conclusao, o.km from reservas.manut_ordens o
         where o.veiculo_id = ap.vid and ap.pid = any(o.planos) and o.status = 'concluida'
         order by o.data_conclusao desc, o.km desc limit 1) u on true
  ), calc as (
    select b.*,
      coalesce(b.u_data, (b.b_ts at time zone 'America/Sao_Paulo')::date) d0,
      coalesce(b.u_km,
        (select k.km from reservas.km_leituras k where k.veiculo_id = b.vid and k.km > 0 and k.registrado_em <= b.b_ts order by k.registrado_em desc limit 1),
        (select k.km from reservas.km_leituras k where k.veiculo_id = b.vid and k.km > 0 order by k.registrado_em asc limit 1),
        b.vkm) k0
    from base b
  ), fin as (
    select c.*, c.k0 + c.pik nk, (c.d0 + make_interval(months => c.pim))::date nd from calc c
  )
  select f.vid, f.pid, f.pnome, f.pik, f.pim, f.d0, f.k0, f.u_data is null, f.vkm,
         f.nk, f.nd, f.nk - f.vkm, f.nd - hoje,
         case when (f.nk is not null and f.nk - f.vkm <= 0) or (f.nd is not null and f.nd - hoje < 0) then 'vencido'
              when (f.nk is not null and f.nk - f.vkm <= f.pak) or (f.nd is not null and f.nd - hoje <= f.pad) then 'alerta'
              else 'ok' end
    from fin f;
end $$;

revoke all on function reservas.salvar_condutor(uuid,jsonb), reservas.excluir_veiculo(uuid) from public, anon;
grant execute on function reservas.salvar_condutor(uuid,jsonb), reservas.excluir_veiculo(uuid), reservas.login_valido(text) to authenticated, service_role;

-- 7) Não deixa reservar com CNH vencida na data da reserva (sem CNH cadastrada = libera)
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
